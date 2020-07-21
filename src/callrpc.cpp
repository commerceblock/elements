#include "chainparamsbase.h"
#include "callrpc.h"
#include "util.h"
#include "utilstrencodings.h"
#include "rpc/protocol.h"

#include "support/events.h"

#include "rpc/client.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/keyvalq_struct.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/http.h>
#include <sstream>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

extern "C" {
    #include "openssl_hostname_validation.h"
}

using stringstream = std::stringstream;
using string = std::string;

static int ignore_cert = 0;

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    std::string body;
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
                printf("https server '%s' has this certificate, "
                       "which looks good to me:\n%s\n",
                       host, cert_str);
                return 1;
        } else {
                printf("Got '%s' for hostname '%s' and certificate:\n%s\n",
                       res_str, host, cert_str);
                return 0;
        }
}


UniValue CallRPC_http(const std::string& strMethod, const UniValue& params, bool connectToMainchain) {
    LogPrintf("CallRPC_http\n");
    std::string strhost = "-rpcconnect";
    std::string strport = "-rpcport";
    std::string struser = "-rpcuser";
    std::string strpassword = "-rpcpassword";

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

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
    
    //if (host.find("infura") == string::npos){
        evhttp_add_header(output_headers, "Host", host.c_str());
        evhttp_add_header(output_headers, "Connection", "close");
        evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());
    //}
    if (connectToMainchain) {
        // Add json content header required by geth rpc api
        evhttp_add_header(output_headers, "Content-Type", "application/json");
    }


    // Attach request data
    std::string strRequest = JSONRPCRequestObj(strMethod, params, 1).write() + "\n";
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);

    LogPrintf("port: %d", port);
    LogPrintf("POST request: %s",strRequest);
    LogPrintf("Host: %s",host.c_str());
    LogPrintf("Connection: %s","close");
    LogPrintf("Authorization: %s", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());


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



UniValue CallRPC_https(const std::string& strMethod, const UniValue& params, bool connectToMainchain) {

    LogPrintf("CallRPC_https\n");
    struct evhttp_uri *http_uri = NULL;
    const char *scheme = NULL;
    const char *host=NULL;
    const char *path=NULL;
    const char *query=NULL;
    string uri;
    const char *crt = NULL;

    std::string struri = "";
    std::string strhost = "-rpcconnect";
    std::string strport = "-rpcport";
    std::string struser = "-rpcuser";
    std::string strpassword = "-rpcpassword";

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    //struct evhttp_connection *evcon = NULL;
//    struct evhttp_request *req;
    int retries = 0;
    int timeout=-1;


    enum { HTTP, HTTPS } type = HTTP;

    struct bufferevent *bev;

    LogPrintf("get port\n");

    int port;

    LogPrintf("get params\n");
    if (connectToMainchain) {
        struri = "-mainchainrpcuri";
        strhost = "-mainchainrpchost";
        strport = "-mainchainrpcport";
        strpassword = "-mainchainrpcpassword";
        struser = "-mainchainrpcuser";
        //port = GetArg(strport, BaseParams().MainchainRPCPort());
    } else {
        port = GetArg(strport, BaseParams().RPCPort());
    }

    LogPrintf("getting uri from arg: %s\n", struri);

    struri = GetArg(struri, "no mainchainrpcuri given");

    LogPrintf("parsing uri: %s\n", struri);

    //Get URI host and scheme
    http_uri = evhttp_uri_parse(struri.c_str());
    if (http_uri == NULL) {
        LogPrintf("malformed url: %s\n", struri);
        throw std::runtime_error("malformed url");
    }

    stringstream ss;
    ss << "getting scheme from http_uri: " << http_uri << std::endl;

    LogPrintf(ss.str());

    scheme = evhttp_uri_get_scheme(http_uri);
    if (scheme == NULL || (strcasecmp(scheme, "https") != 0 &&
                               strcasecmp(scheme, "http") != 0)) {
            LogPrintf("url must be http or https\n");
            throw std::runtime_error("url must be http or https");
    }

    LogPrintf("getting host\n");

    host = evhttp_uri_get_host(http_uri);
    if (host == NULL) {
        throw std::runtime_error("url must have a host");
    }
    
    LogPrintf("getting port\n");

    port = evhttp_uri_get_port(http_uri);
    if (port == -1) {
        port = (strcasecmp(scheme, "http") == 0) ? 80 : 443;
    }

    LogPrintf("port: %d\n",port);

    path = evhttp_uri_get_path(http_uri);
        if (strlen(path) == 0) {
                path = "/";
    }

    LogPrintf("path: %s\n",path);

    LogPrintf("getting query\n");
    query = evhttp_uri_get_query(http_uri);
    ss.str("");
    if (query == NULL) {
        LogPrintf("query is null\n");
        ss << uri << path << std::endl;
        uri = ss.str().c_str();
    } else {
        LogPrintf("query: %s\n", query);
        ss << uri << path << "?" << query << std::endl;
        uri = ss.str().c_str();
    }

    LogPrintf("uri: %s\n",uri);    



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
                        throw std::runtime_error("error adding cert to store");
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

        
    // Obtain event base
    raii_event_base base = obtain_event_base();


    // Create OpenSSL bufferevent and stack evhttp on top of it                           
    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        throw std::runtime_error("cSSL_new()");
    }



    #ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        // Set hostname for SNI extension                                                     
    SSL_set_tlsext_host_name(ssl, host);
    #endif

   
        if (strcasecmp(scheme, "http") == 0) {
            bev = bufferevent_socket_new(base.get(), -1, BEV_OPT_CLOSE_ON_FREE);
        } else {
                type = HTTPS;
                bev = bufferevent_openssl_socket_new(base.get(), -1, ssl,
                        BUFFEREVENT_SSL_CONNECTING,
                        BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        }

        if (bev == NULL) {
            throw std::runtime_error("bufferevent_openssl_socket_new() failed\n");
        }

        bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

        // For simplicity, we let DNS resolution block. Everything else should be             
        // asynchronous though.   


        // Synchronously look up hostname
        raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
        evhttp_connection_set_timeout(evcon.get(), GetArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));

        bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

        //HTTPReply response;
        // Fire off the request                                                               
        //req = evhttp_request_new(http_request_done, (void*)&response);
        HTTPReply response;
        raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
        if (req == NULL)
            throw std::runtime_error("create http request failed");
        #if LIBEVENT_VERSION_NUMBER >= 0x02010300
            evhttp_request_set_error_cb(req.get(), http_error_cb);
        #endif


        if (req == NULL) {
            throw std::runtime_error("evhttp_connection_base_bufferevent_new() failed\n");
        }

        struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
        LogPrintf("adding Host to header: %s\n", host);
        evhttp_add_header(output_headers, "Host", host);
        evhttp_add_header(output_headers, "Connection", "close");
        evhttp_add_header(output_headers, "Content-Type", "application/json");




/// from ---


    // Attach request data
    std::string strRequest = JSONRPCRequestObj(strMethod, params, 1).write();
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);

    LogPrintf("port: %d\n", port);
    LogPrintf("POST request: %s\n",strRequest);


    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());
    size_t bytes = strRequest.size()-1;
    LogPrintf("output buffer: %s\n", output_buffer);


    //Add content length header
    //char buf[1024];
    //evutil_snprintf(buf, sizeof(buf)-1, "%lu", (unsigned long)bytes);
    //evhttp_add_header(output_headers, "Content-Length", buf);


    LogPrintf("sending request\n");

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, uri.c_str());
    //req.release(); // ownership moved to evcon in above call

    LogPrintf("request result: %d\n", r);

    req->release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    LogPrintf("event_base_dispatch\n");
    event_base_dispatch(base.get());
    LogPrintf("dispatched -checking response\n");
    ss.str("");
    ss << "checking response - body: " << response.body << " status: " << response.status << " error: " << response.error << std::endl;
    LogPrintf(ss.str());

    LogPrintf("checked response\n");

    if (response.status == 0){
        LogPrintf("connect to server failed\n");
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
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

    LogPrintf("parsing reply");
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
