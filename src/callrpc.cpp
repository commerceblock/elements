#include "chainparamsbase.h"
#include "callrpc.h"
#include "util.h"
#include "utilstrencodings.h"
#include "rpc/protocol.h"

#include "support/events.h"

#include "rpc/client.h"

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include <event2/util.h>
#include <event2/event.h>
#include <sstream>
#include <string>
#include <list>
#include <tuple>

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define snprintf _snprintf
#define strcasecmp _stricmp 
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

extern "C" {
    #include "openssl_hostname_validation.h"
}

using stringstream = std::stringstream;
using string = std::string;
using std::list;
//template <typename T> using list<T> = std::list<T>;
using std::get;
using osl_error = std::tuple<unsigned long, string>;
using socket_error = std::tuple<int, string>;

static int ignore_cert = 0;

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    std::string body;
};

/** Reply structure for request_done to fill in */
struct HTTPSReply
{
  HTTPSReply(): status(0), body(""), sock_err(socket_error(-1,"")) {}

    int status;
    std::string body;
    socket_error sock_err;
    list<osl_error> osl_errors;
    struct bufferevent* bev;
};


const char *http_errorstring(int code)
{
    switch(code) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
#endif
    default:
        return "unknown";
    }
}

static void
https_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPSReply *reply = static_cast<HTTPSReply*>(ctx);

    char buffer[1024];
    int nread, ntotal(0);

    if (!req || !evhttp_request_get_response_code(req)) {
        if(req) reply->status=evhttp_request_get_response_code(req);

        struct bufferevent *bev = (struct bufferevent *) reply->bev;
        unsigned long oslerr;
        int errcode = EVUTIL_SOCKET_ERROR();

        while ((oslerr = bufferevent_get_openssl_error(bev))) {
            ERR_error_string_n(oslerr, buffer, sizeof(buffer));
            reply->osl_errors.push_back(osl_error{oslerr, string(buffer)});
        }

        if (! reply->osl_errors.size()){
            reply->sock_err = {errcode, string(evutil_socket_error_to_string(errcode))};
        }
        return;
    }

    reply->status=evhttp_request_get_response_code(req);
 
    stringstream ss;
    while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
            buffer, sizeof(buffer)))
           > 0) {
        /* These are just arbitrary chunks of 256 bytes.
         * They are not lines, so we can't treat them as such. */
        ss << buffer;
        ntotal+=nread;
    }
    ss << std::endl;
    reply->body = ss.str().substr(0,ntotal+1);
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}


#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}
#endif

UniValue CallRPC_http(const std::string& strMethod, const UniValue& params, bool connectToMainchain) {
    std::string strhost = "-rpcconnect";
    std::string strport = "-rpcport";
    std::string struser = "-rpcuser";
    std::string strpassword = "-rpcpassword";

    int port = GetArg(strport, BaseParams().RPCPort());

    if (connectToMainchain) {
        strhost = "-mainchainrpchost";
        strport = "-mainchainrpcport";
        strpassword = "-mainchainrpcpassword";
        struser = "-mainchainrpcuser";
        port = GetArg(strport, BaseParams().MainchainRPCPort());
    }

    std::string host = GetArg(strhost, DEFAULT_RPCCONNECT);
    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_timeout(evcon.get(), GetArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == NULL)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    // Get credentials
    std::string strRPCUserColonPass;
    if (GetArg(strpassword, "") == "") {
        // Try fall back to cookie-based authentication if no password is provided
        if (!connectToMainchain && !GetAuthCookie(&strRPCUserColonPass)) {
            throw std::runtime_error(strprintf(
                _("Could not locate RPC credentials. No authentication cookie could be found, and no rpcpassword is set in the configuration file (%s)"),
                    GetConfigFile(GetArg("-conf", BITCOIN_CONF_FILENAME)).string().c_str()));
        }
    } else {
        if (struser == "")
            throw std::runtime_error(
                 _("Could not locate mainchain RPC credentials. No authentication cookie could be found, and no mainchainrpcuser is set in the configuration file"));
        else
            strRPCUserColonPass = GetArg(struser, "") + ":" + GetArg(strpassword, "");
    }

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    if (connectToMainchain) {
        // Add json content header required by geth rpc api
        evhttp_add_header(output_headers, "Content-Type", "application/json");
    }
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequestObj(strMethod, params, 1).write() + "\n";
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, "/");
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        if (connectToMainchain)
            throw std::runtime_error("incorrect mainchainrpcuser or mainchainrpcpassword (authorization failed)");
        else
            throw std::runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}


UniValue CallRPC(const std::string& strMethod, const UniValue& params, bool connectToMainchain)
{

    std::string uri;
    if (connectToMainchain){
        if (GetArg("-mainchainrpcuri", "").length()) {
            return CallRPC_https(strMethod, params, connectToMainchain);
        }
    }
    return CallRPC_http(strMethod, params, connectToMainchain);
}


UniValue GetEthTransaction(const uint256& hash)
{
    try {
        UniValue params(UniValue::VARR);
        params.push_back("0x" + hash.GetHex());
        UniValue reply = CallRPC("eth_getTransactionReceipt", params, true);
        if (!find_value(reply, "error").isNull())
            return find_value(reply, "error");
        return find_value(reply, "result");
    } catch (CConnectionFailed& e) {
        stringstream ss;
        ss << "ERROR: Lost connection to geth RPC, you will want to restart after fixing this!: "
            << e.what() << std::endl;
        LogPrintf(ss.str());
        return false;
    } catch (...) {
        LogPrintf("ERROR: Failure connecting to geth RPC, you will want to restart after fixing this!\n");
        return false;
    }
    return true;
}

bool IsConfirmedEthBlock(const int64_t& nHeight, int nMinConfirmationDepth)
{
    try {
        UniValue params(UniValue::VARR);
        UniValue reply = CallRPC("eth_blockNumber", params, true);
        if (!find_value(reply, "error").isNull())
            return false;
        UniValue result = find_value(reply, "result");
        if (!result.isStr())
            return false;
        auto nLatestHeight = std::strtoll(result.get_str().c_str(), NULL, 16);
        if (nLatestHeight == 0) { // still syncing
            UniValue reply = CallRPC("eth_syncing", params, true);
            if (!find_value(reply, "error").isNull())
                return false;
            UniValue result = find_value(reply, "result");
            nLatestHeight = std::strtoll(find_value(result, "highestBlock").get_str().c_str(), NULL, 16);
        }
        return nLatestHeight - nHeight > nMinConfirmationDepth;
    } catch (CConnectionFailed& e) {
        LogPrintf("ERROR: Lost connection to geth RPC, you will want to restart after fixing this!\n");
        return false;
    } catch (...) {
        LogPrintf("ERROR: Failure connecting to geth RPC, you will want to restart after fixing this!\n");
        return false;
    }
    return true;
}

bool IsConfirmedBitcoinBlock(const uint256& hash, int nMinConfirmationDepth)
{
    try {
        UniValue params(UniValue::VARR);
        params.push_back(hash.GetHex());
        UniValue reply = CallRPC("getblockheader", params, true);
        if (!find_value(reply, "error").isNull())
            return false;
        UniValue result = find_value(reply, "result");
        if (!result.isObject())
            return false;
        result = find_value(result.get_obj(), "confirmations");
        return result.isNum() && result.get_int64() >= nMinConfirmationDepth;
    } catch (CConnectionFailed& e) {
        LogPrintf("ERROR: Lost connection to bitcoind RPC, you will want to restart after fixing this!\n");
        return false;
    } catch (...) {
        LogPrintf("ERROR: Failure connecting to bitcoind RPC, you will want to restart after fixing this!\n");
        return false;
    }
    return true;
}


/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
    char cert_str[256];
    const char *host = (const char *) arg;
    const char *res_str = "X509_verify_cert failed";
    HostnameValidationResult res = Error;

    /* This is the function that OpenSSL would call if we hadn't called
     * SSL_CTX_set_cert_verify_callback().  Therefore, we are "wrapping"
     * the default functionality, rather than replacing it. */
    int ok_so_far = 0;

    X509 *server_cert = NULL;

    if (ignore_cert) {
        return 1;
    }

    ok_so_far = X509_verify_cert(x509_ctx);

    server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

    if (ok_so_far) {
        res = validate_hostname(host, server_cert);

        switch (res) {
        case MatchFound:
            res_str = "MatchFound";
            break;
        case MatchNotFound:
            res_str = "MatchNotFound";
            break;
        case NoSANPresent:
            res_str = "NoSANPresent";
            break;
        case MalformedCertificate:
            res_str = "MalformedCertificate";
            break;
        case Error:
            res_str = "Error";
            break;
        default:
            res_str = "WTF!";
            break;
        }
    }

    X509_NAME_oneline(X509_get_subject_name (server_cert),
              cert_str, sizeof (cert_str));

    if (res == MatchFound) {
        LogPrintf("https server '%s' has this certificate, "
               "which looks good to me:\n%s\n",
               host, cert_str);
        return 1;
    } else {
        LogPrintf("Got '%s' for hostname '%s' and certificate:\n%s\n",
               res_str, host, cert_str);
        return 0;
    }
}

#ifdef _WIN32
static int
add_cert_for_store(X509_STORE *store, const char *name)
{
    HCERTSTORE sys_store = NULL;
    PCCERT_CONTEXT ctx = NULL;
    int r = 0;

    sys_store = CertOpenSystemStore(0, name);
    if (!sys_store) {
        err("failed to open system certificate store");
        return -1;
    }
    while ((ctx = CertEnumCertificatesInStore(sys_store, ctx))) {
        X509 *x509 = d2i_X509(NULL, (unsigned char const **)&ctx->pbCertEncoded,
            ctx->cbCertEncoded);
        if (x509) {
            X509_STORE_add_cert(store, x509);
            X509_free(x509);
        } else {
            r = -1;
            err_openssl("d2i_X509");
            break;
        }
    }
    CertCloseStore(sys_store, 0);
    return r;
}
#endif

UniValue CallRPC_https(const std::string& strMethod, const UniValue& params, bool connectToMainchain) {

    string url = GetArg(string("-mainchainrpcuri"), "");
    string strpassword = "-mainchainrpcpassword";
    string struser = "-mainchainrpcuser";

    int r;
    struct event_base *base = NULL;
    struct evhttp_uri *http_uri = NULL;

    const char *crt = NULL;
    const char *scheme, *host, *path, *query;
    char uri[256];
    int port;
    int retries = 0;
    int timeout = -1;

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    struct bufferevent *bev;
    struct evhttp_connection *evcon = NULL;
    struct evhttp_request *req;
    struct evkeyvalq *output_headers;
    struct evbuffer *output_buffer;

    enum { HTTP, HTTPS } type = HTTP;

    if (!url.length()) {
        throw std::runtime_error("no url");
    }

#ifdef _WIN32
    {
        WORD wVersionRequested;
        WSADATA wsaData;
        int err;

        wVersionRequested = MAKEWORD(2, 2);

        err = WSAStartup(wVersionRequested, &wsaData);
        if (err != 0) {
            printf("WSAStartup failed with error: %d\n", err);
            throw std::runtime_error("WSAStartup failed with error: %d\n", err);
        }
    }
#endif // _WIN32
    http_uri = evhttp_uri_parse(url.c_str());
    if (http_uri == NULL) {
        throw std::runtime_error("malformed url");
    }

    scheme = evhttp_uri_get_scheme(http_uri);
    if (scheme == NULL || (strcasecmp(scheme, "https") != 0 &&
                      
                           strcasecmp(scheme, "http") != 0)) {
        throw std::runtime_error("url must be http or https");
    }

    host = evhttp_uri_get_host(http_uri);
    if (host == NULL) {
        throw std::runtime_error("url must have a host");
    }

    port = evhttp_uri_get_port(http_uri);
    if (port == -1) {
        port = (strcasecmp(scheme, "http") == 0) ? 80 : 443;
    }

    path = evhttp_uri_get_path(http_uri);
    if (strlen(path) == 0) {
        path = "/";
    }

    query = evhttp_uri_get_query(http_uri);
    if (query == NULL) {
        snprintf(uri, sizeof(uri) - 1, "%s", path);
    } else {
        snprintf(uri, sizeof(uri) - 1, "%s?%s", path, query);
    }
    uri[sizeof(uri) - 1] = '\0';

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
    // Initialize OpenSSL
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif

    /* Create a new OpenSSL context */
    ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!ssl_ctx) {
        throw std::runtime_error("SSL_CTX_new");
    }

    if (crt == NULL) {
        X509_STORE *store;
        /* Attempt to use the system's trusted root certificates. */
        store = SSL_CTX_get_cert_store(ssl_ctx);
#ifdef _WIN32
        if (add_cert_for_store(store, "CA") < 0 ||
            add_cert_for_store(store, "AuthRoot") < 0 ||
            add_cert_for_store(store, "ROOT") < 0) {
            throw std::runtime_error("cert store error");
        }
#else // _WIN32
        if (X509_STORE_set_default_paths(store) != 1) {
            throw std::runtime_error("X509_STORE_set_default_paths");
        }
#endif // _WIN32
    } else {
        if (SSL_CTX_load_verify_locations(ssl_ctx, crt, NULL) != 1) {
            throw std::runtime_error("SSL_CTX_load_verify_locations");
        }
    }
    /* Ask OpenSSL to verify the server certificate.  Note that this
     * does NOT include verifying that the hostname is correct.
     * So, by itself, this means anyone with any legitimate
     * CA-issued certificate for any website, can impersonate any
     * other website in the world.  This is not good.  See "The
     * Most Dangerous Code in the World" article at
     * https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html
     */
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    /* This is how we solve the problem mentioned in the previous
     * comment.  We "wrap" OpenSSL's validation routine in our
     * own routine, which also validates the hostname by calling
     * the code provided by iSECPartners.  Note that even though
     * the "Everything You've Always Wanted to Know About
     * Certificate Validation With OpenSSL (But Were Afraid to
     * Ask)" paper from iSECPartners says very explicitly not to
     * call SSL_CTX_set_cert_verify_callback (at the bottom of
     * page 2), what we're doing here is safe because our
     * cert_verify_callback() calls X509_verify_cert(), which is
     * OpenSSL's built-in routine which would have been called if
     * we hadn't set the callback.  Therefore, we're just
     * "wrapping" OpenSSL's routine, not replacing it. */
    SSL_CTX_set_cert_verify_callback(ssl_ctx, cert_verify_callback,
                      (void *) host);

    // Create event base
    base = event_base_new();
    if (!base) {
        throw std::runtime_error("event_base_new()");
    }

    // Create OpenSSL bufferevent and stack evhttp on top of it
    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        throw std::runtime_error("SSL_new()");
    }

    #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    // Set hostname for SNI extension
    SSL_set_tlsext_host_name(ssl, host);
    #endif

    if (strcasecmp(scheme, "http") == 0) {
        bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    } else {
        type = HTTPS;
        bev = bufferevent_openssl_socket_new(base, -1, ssl,
            BUFFEREVENT_SSL_CONNECTING,
            BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    }

    if (bev == NULL) {
        throw std::runtime_error("bufferevent_openssl_socket_new() failed");
    }

    bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

    // For simplicity, we let DNS resolution block. Everything else should be
    // asynchronous though.
    evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
        host, port);
    if (evcon == NULL) {
        throw std::runtime_error("evhttp_connection_base_bufferevent_new() failed");
    }

    if (retries > 0) {
        evhttp_connection_set_retries(evcon, retries);
    }
    if (timeout >= 0) {
        evhttp_connection_set_timeout(evcon, timeout);
    }

    // Fire off the request
    HTTPSReply response;
    response.bev = bev;
    req = evhttp_request_new(https_request_done, (void*)&response);
    if (req == NULL) {
        throw std::runtime_error("evhttp_request_new() failed");
    }


    output_headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(output_headers, "Host", host);
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Content-Type", "application/json");

    // Attach request data
    std::string strRequest = JSONRPCRequestObj(strMethod, params, 1).write() + "\n";
    output_buffer = evhttp_request_get_output_buffer(req);
    assert(output_buffer);

    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());
    

    r = evhttp_make_request(evcon, req, EVHTTP_REQ_POST, uri);
    if (r != 0) {
        throw std::runtime_error("evhttp_make_request() failed");
    }

    event_base_dispatch(base);

    stringstream ss;
    if (response.status == 0){
        ss << ("error: ");
        if (response.osl_errors.size() > 0 ){
            ss << response.osl_errors.size() << " osl errors: " << std::endl;
	    int nerr=0;
            for (auto& err : response.osl_errors) {
                ss << "error " << nerr << ": " << get<1>(err) << ", code(" << get<0>(err) << ")" << std::endl;
            }
        } else {
            ss << "socket error: " << get<1>(response.sock_err) << ", code(" << get<0>(response.sock_err) << ")" << std::endl;
        }   

        throw CConnectionFailed(ss.str());
    }
    else if (response.status == HTTP_UNAUTHORIZED)
        if (connectToMainchain)
            throw std::runtime_error("incorrect mainchainrpcuser or mainchainrpcpassword (authorization failed)");
        else
            throw std::runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");


    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body)){
            throw std::runtime_error("couldn't parse reply from server");
    }
    const UniValue& reply = valReply.get_obj();
    if (reply.empty()){
        throw std::runtime_error("expected reply to have result, error and id properties");
    }


    //cleanup
    if (evcon)
        evhttp_connection_free(evcon);
    if (http_uri)
        evhttp_uri_free(http_uri);
    if (base)
        event_base_free(base);

    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    if (type == HTTP && ssl)
        SSL_free(ssl);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
    EVP_cleanup();
    ERR_free_strings();

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    ERR_remove_state(0);
#else
    ERR_remove_thread_state(NULL);
#endif

    CRYPTO_cleanup_all_ex_data();

    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L) */

#ifdef _WIN32
    WSACleanup();
#endif


    return reply;
}

