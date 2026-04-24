module Blossom

import HTTP, JSON, URIs, Base64, SHA, Sockets
using DataStructures: CircularBuffer

import ..Utils
import ..Nostr
import ..Postgres
import ..Media

PORT = Ref(21000)
DB = Ref(:membership)

BASE_URL = Ref("https://blossom.primal.net")

PRINT_EXCEPTIONS = Ref(true)

server = Ref{Any}(nothing)
router = Ref{Any}(nothing)

exceptions = CircularBuffer(200)

est = Ref{Any}(nothing)

pex(query::String, params=[]) = Postgres.execute(DB[], replace(query, '?'=>'$'), params)
pex(server::Symbol, query::String, params=[]) = Postgres.execute(server, replace(query, '?'=>'$'), params)

struct BlossomException <: Exception
    status::Int
    message::String
end

function blossom_error(status::Int, message::String)
    throw(BlossomException(status, message))
end

exceptions_lock = ReentrantLock()
function catch_exception(body::Function, handler::Symbol, args...)
    try
        body()
    catch ex
        lock(exceptions_lock) do
            push!(exceptions, (handler, time(), ex, args...))
            PRINT_EXCEPTIONS[] && Utils.print_exceptions()
        end
        if ex isa BlossomException
            HTTP.Response(ex.status, response_headers("text/plain"; extra=["X-Reason"=>ex.message]), ex.message)
        else
            HTTP.Response(500, response_headers("text/plain"; extra=["X-Reason"=>"unspecified error"]), "error")
        end
    end
end

function start(cache_storage)
    @assert isnothing(server[])

    est[] = cache_storage

    router[] = HTTP.Router()
    server[] = HTTP.serve!(router[], "0.0.0.0", PORT[])

    for path in ["/**", "/"]
        HTTP.register!(router[], path, blossom_handler)
    end

    nothing
end

function stop()
    @assert !isnothing(server[])
    close(server[])
    server[] = nothing
end

function mimetype_for_ext(ext::String)
    for (mimetype, ext2) in Main.Media.mimetype_ext
        if ext2 == ext
            return mimetype
        end
    end
    nothing
end

function response_headers(content_type="application/json"; extra=[])
    HTTP.Headers(collect(Dict(["Content-Type"=>content_type,
                               "Access-Control-Allow-Origin"=>"*",
                               "Access-Control-Allow-Methods"=>"*",
                               "Access-Control-Allow-Headers"=>"*",
                               extra...
                              ])))
end

function get_header(headers, header)
    for (k, v) in collect(headers)
        if lowercase(k) == lowercase(header)
            return v
        end
    end
    nothing
end

function find_blob(req_target)
    find_upload(req_target)
end

function find_upload(req_target)
    h, ext = splitext(req_target[2:end])
    h = lowercase(h)
    sha256 = try hex2bytes(h) catch _ return nothing end
    for (mimetype, size, path, pubkey, key) in pex("select mimetype, size, path, pubkey, key::varchar 
                                             from media_uploads 
                                             where sha256 = ?1 and media_block_id is null limit 1", 
                                             [sha256])[2]
        kh = splitpath(splitext(path)[1])[end]
        for (media_url, mimetype, size, storage_provider) in pex(:p0, "
                                                           select ms.media_url, ms.content_type, ms.size, ms.storage_provider 
                                                           from media_storage ms, media_storage_priority msp
                                                           where ms.h = ?1 and ms.media_block_id is null and msp.storage_provider = ms.storage_provider
                                                           order by msp.priority limit 1", 
                                                           [kh])[2]
            storage_provider = Symbol(storage_provider)
            return (; media_url, storage_provider, path, mimetype, size, sha256, pubkey=Nostr.PubKeyId(pubkey))
        end
        for mp in Main.Media.MEDIA_PATHS[Main.App.UPLOADS_DIR[]]
            if mp[1] == :local
                filepath = join(split(mp[3], '/')[1:end-1], '/') * path
                media_url = "https://media.primal.net$path"
                try isfile(filepath) && return (; media_url, storage_provider=nothing, filepath, path, mimetype, size, sha256, pubkey=Nostr.PubKeyId(pubkey))
                catch _ end
            end
        end
    end
    nothing
end

function base64url_decode_nopad(s::AbstractString)
    if !isnothing(match(r"^[A-Za-z0-9_-]+=*$", s))
        stripped = replace(String(s), r"=+$" => "")
        mod4 = length(stripped) % 4
        mod4 == 1 && blossom_error(401, "invalid auth event")
        padded = replace(replace(stripped, '-'=>'+'), '_'=>'/') * repeat("=", mod(4 - mod4, 4))
        try
            return Base64.base64decode(padded)
        catch _
        end
    end
    try
        Base64.base64decode(s)
    catch _
        blossom_error(401, "invalid auth event")
    end
end

function is_valid_server_domain(domain::AbstractString)
    !isnothing(match(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", domain))
end

function host_domain(host)
    isnothing(host) && return nothing
    host = lowercase(strip(String(host)))
    isempty(host) && return nothing
    if startswith(host, '[')
        return nothing
    end
    domain = split(host, ':'; limit=2)[1]
    is_valid_server_domain(domain) ? domain : nothing
end

function base_url_domain()
    try
        host_domain(URIs.parse_uri(BASE_URL[]).host)
    catch _
        nothing
    end
end

function current_server_domains(req)
    domains = Set{String}()
    # Accept either proxy-forwarded Host or configured public BASE_URL for scoped tokens.
    for domain in (host_domain(get_header(req.headers, "Host")), base_url_domain())
        isnothing(domain) || push!(domains, domain)
    end
    domains
end

function ipv4_octets(ip::AbstractString)
    parts = split(String(ip), '.')
    length(parts) == 4 || return nothing
    octets = Int[]
    for part in parts
        isempty(part) && return nothing
        octet = try parse(Int, part) catch _ return nothing end
        0 <= octet <= 255 || return nothing
        push!(octets, octet)
    end
    octets
end

function is_blocked_ipv4(ip::AbstractString)
    octets = ipv4_octets(ip)
    isnothing(octets) && return false
    a, b = octets[1], octets[2]
    a == 0 || a == 10 || a == 127 ||
    (a == 100 && 64 <= b <= 127) ||
    (a == 169 && b == 254) ||
    (a == 172 && 16 <= b <= 31) ||
    (a == 192 && b == 168) ||
    (a == 198 && 18 <= b <= 19) ||
    a >= 224
end

function is_blocked_ipv6(ip::AbstractString)
    s = lowercase(String(ip))
    s == "::" || s == "::1" || startswith(s, "fe80:") || startswith(s, "fc") || startswith(s, "fd")
end

function is_blocked_mirror_ip(ip)
    s = string(ip)
    is_blocked_ipv4(s) || occursin(':', s) && is_blocked_ipv6(s)
end

function has_spoofed_primal_direct_host(host::AbstractString)
    for direct_host in ("primal.net", "primalnode.net", "primaldata.s3", "primaldata.fsn1")
        if occursin(direct_host, host) && !(host == direct_host || endswith(host, ".$direct_host"))
            return true
        end
    end
    false
end

function validate_mirror_url(url::String)
    u = try URIs.parse_uri(url) catch _ blossom_error(400, "invalid mirror URL") end
    scheme = isnothing(u.scheme) ? "" : lowercase(String(u.scheme))
    scheme == "https" || blossom_error(400, "invalid mirror URL scheme")
    host = host_domain(u.host)
    isnothing(host) && blossom_error(400, "invalid mirror URL host")
    has_spoofed_primal_direct_host(host) && blossom_error(400, "invalid mirror URL host")
    ips = try Sockets.getalladdrinfo(host) catch _ blossom_error(400, "invalid mirror URL host") end
    isempty(ips) && blossom_error(400, "invalid mirror URL host")
    any(is_blocked_mirror_ip, ips) && blossom_error(400, "invalid mirror URL host")
    path = isnothing(u.path) ? "" : String(u.path)
    m = match(r"/(?:[^/?#]*/)*([0-9a-fA-F]{64})(?:\.[^/?#]*)?$", path)
    isnothing(m) && blossom_error(400, "mirror URL missing sha256")
    lowercase(m[1]), string(u)
end

function check_action(req, action::String; x_tag_hash=nothing)
    parts = []
    if !isnothing(local v = get_header(req.headers, "Authorization"))
        parts = split(v)
    end
    length(parts) == 2 || blossom_error(401, "missing auth event")
    parts[1] == "Nostr" || blossom_error(401, "invalid auth event")
    e = try
        Nostr.Event(JSON.parse(String(base64url_decode_nopad(parts[2]))))
    catch ex
        ex isa BlossomException && rethrow()
        blossom_error(401, "invalid auth event")
    end
    Nostr.verify(e) || blossom_error(401, "auth event verification failed")
    e.kind == 24242 || blossom_error(401, "wrong kind in auth event")
    now = trunc(Int, time())
    e.created_at <= now || blossom_error(401, "auth event created in the future")
    action_ok = false
    expiration_ok = false
    server_tags = String[]
    for t in e.tags
        if length(t.fields) >= 2
            if t.fields[1] == "expiration"
                expiration = try parse(Int, t.fields[2]) catch _ blossom_error(401, "invalid expiration tag") end
                expiration_ok |= expiration > now
            elseif t.fields[1] == "t"
                action_ok |= action == t.fields[2] 
            elseif t.fields[1] == "server"
                t.fields[2] isa AbstractString || blossom_error(401, "invalid server tag")
                server = lowercase(String(t.fields[2]))
                is_valid_server_domain(server) || blossom_error(401, "invalid server tag")
                push!(server_tags, server)
            end
        end
    end
    expiration_ok || blossom_error(401, "auth event expired")
    action_ok || blossom_error(401, "invalid action in auth event")
    if !isempty(server_tags)
        domains = current_server_domains(req)
        any(server -> server in domains, server_tags) || blossom_error(401, "invalid server tag")
    end
    if !isnothing(x_tag_hash)
        check_x_tag(e, x_tag_hash)
    end
    e
end

function check_x_tag(e::Nostr.Event, x_tag_hash; status=401)
    expected = bytes2hex(x_tag_hash)
    for t in e.tags
        if length(t.fields) >= 2 && t.fields[1] == "x"
            t.fields[2] == expected && return nothing
        end
    end
    blossom_error(status, "invalid x tag")
end

function blossom_handler(req::HTTP.Request)
    catch_exception(:blossom_handler, req) do
        host = get_header(req.headers, "Host")
        # @show (req.method, req.target)
        
        if req.method == "OPTIONS"
            return HTTP.Response(200, response_headers("text/plain"; extra=[
                                                                            "Access-Control-Allow-Headers"=>"Authorization, *",
                                                                            "Access-Control-Allow-Methods"=>"GET, PUT, DELETE",
                                                                           ]), "ok")

        elseif req.method == "GET"
            if req.target == "/"
                return HTTP.Response(200, response_headers("text/plain"), "Welcome to Primal Blossom server. Implemented: BUD-01, BUD-02, BUD-04, BUD-05")

            elseif startswith(req.target, "/list/")
                pk = Nostr.PubKeyId(string(split(req.target, '/')[end]))
                res = []
                for (mimetype, created_at, path, size, sha256) in pex("select mimetype, created_at, path, size, sha256 from media_uploads where pubkey = ?1", [pk])[2]
                    # _, ext = splitext(path)
                    # mimetype = mimetype_for_ext(ext)
                    ext = get(Main.Media.mimetype_ext, mimetype, "")
                    push!(res, (;
                                url="$(BASE_URL[])/$(bytes2hex(sha256))$(ext)",
                                sha256=bytes2hex(sha256),
                                size,
                                type=mimetype,
                                uploaded=created_at,
                               ))
                end
                return HTTP.Response(200, response_headers(), JSON.json(res))

            elseif !isnothing(match(r"^/[0-9a-fA-F]{64}", req.target))
                # @show req.target
                r = find_blob(req.target)
                if !isnothing(r)
                    # return HTTP.Response(302, response_headers(r.mimetype; extra=["Location"=>"https://primal.b-cdn.net/media-cache?s=o&a=1&u=$(URIs.escapeuri(r.media_url))"]), 
                    #                      "redirecting")
                    return HTTP.Response(302, response_headers(r.mimetype; extra=["Location"=>r.media_url]), 
                                         "redirecting")
                else
                    blossom_error(404, "not found")
                end
            end

        elseif req.method == "HEAD"
            if req.target in ["/upload", "/media"]
                h = 
                try hex2bytes(get_header(req.headers, "X-SHA-256"))
                catch _ blossom_error(401, "X-SHA-256 request header is missing") end
                check_action(req, "upload"; x_tag_hash=h)
                return HTTP.Response(200, response_headers("text/plain"), "ok")
            else
                r = find_blob(req.target)
                if !isnothing(r)
                    return HTTP.Response(200, response_headers(r.mimetype; extra=["Content-Length"=>string(r.size)]), "")
                else
                    blossom_error(404, "not found")
                end
            end

        elseif req.method == "DELETE"
            r = find_upload(req.target)
            isnothing(r) && blossom_error(404, "not found")
            e = check_action(req, "delete"; x_tag_hash=r.sha256)
            if !isnothing(r) && r.pubkey == e.pubkey
                Main.InternalServices.purge_media_(e.pubkey, r.media_url; reason="delete from blossom", extra=(; initiator_pubkey=e.pubkey))
                return HTTP.Response(200, response_headers("text/plain"), "ok")
            else
                blossom_error(404, "not found")
            end

        elseif req.method == "PUT"
            # push!(Main.stuff, (:blossomupload, req))
            if req.target == "/mirror"
                url = try
                    body = JSON.parse(String(req.body))
                    body isa Dict || blossom_error(400, "invalid mirror request")
                    u = get(body, "url", nothing)
                    u isa String || blossom_error(400, "invalid mirror request")
                    u
                catch ex
                    ex isa BlossomException && rethrow()
                    blossom_error(400, "invalid mirror request")
                end
                hash_hex, url = validate_mirror_url(url)
                h = hex2bytes(hash_hex)
                e = check_action(req, "upload"; x_tag_hash=h)
                data = try
                    Media.download(est[], url; timeout=300)
                catch _
                    blossom_error(502, "failed to fetch mirror URL")
                end
                SHA.sha256(data) == h || blossom_error(409, "x tag does not match mirrored content")
                return import_blob(e, data; strip_metadata=false)
            else
                data = collect(req.body)
                e = check_action(req, "upload"; x_tag_hash=SHA.sha256(data))
                strip_metadata = req.target == "/media"
                return import_blob(e, data; strip_metadata)
            end
        end

        blossom_error(404, "not found")
    end
end

function import_blob(e::Nostr.Event, data::Vector{UInt8}; strip_metadata::Bool)
    h = SHA.sha256(data)
    r = JSON.parse([x for x in Main.App.import_upload_2(est[], e.pubkey, data; strip_metadata)
                    if x.kind == Int(Main.App.UPLOADED_2)][1].content)
    sha256 = hex2bytes(r["sha256"])
    strip_metadata || @assert h == sha256
    for (mimetype, created_at, path, size) in pex("select mimetype, created_at, path, size from media_uploads where sha256 = ?1", [sha256])[2]
        # @show path
        # _, ext = splitext(path)
        # mimetype = mimetype_for_ext(ext)
        ext = get(Main.Media.mimetype_ext, mimetype, "")
        return HTTP.Response(200, response_headers("application/json"), 
                             JSON.json((;
                                        url="$(BASE_URL[])/$(bytes2hex(sha256))$(ext)",
                                        sha256=bytes2hex(sha256),
                                        size,
                                        type=mimetype,
                                        uploaded=created_at,
                                       )))
    end
    blossom_error(404, "not found")
end

end
