#include "curlpp/Easy.hpp"
#include "curlpp/Options.hpp"
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
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    if (connectToMainchain) {
        // Add json content header required by geth rpc api
        evhttp_add_header(output_headers, "Content-Type", "application/json");
    }


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
    std::stringstream ss;
    try {
        UniValue params(UniValue::VARR);
        UniValue reply = CallRPC("eth_blockNumber", params, true);
        if (!find_value(reply, "error").isNull()){
            LogPrintf("eth_blockNumber returned Null\n");
            return false;
        }
        UniValue result = find_value(reply, "result");
        if (!result.isStr()){
            LogPrintf("Result is not a string\n");
            return false;
        }
        auto nLatestHeight = std::strtoll(result.get_str().c_str(), NULL, 16);
        if (nLatestHeight == 0) { // still syncing
            UniValue reply = CallRPC("eth_syncing", params, true);
            if (!find_value(reply, "error").isNull()){
                ss.str("eth_syncing returned an error: ");
                ss << find_value(reply, "error").get_str() << std::endl;
                LogPrintf(ss.str());
                return false;
            }
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


UniValue CallRPC_https(const std::string& strMethod, const UniValue& params, 
    bool connectToMainchain) {
    cURLpp::Easy request;
    string url = GetArg(string("-mainchainrpcuri"), "");
    request.setOpt(new cURLpp::Options::Url(url));
    request.setOpt(new curlpp::options::Verbose(true));

    std::list<std::string> header;
    //evhttp_add_header(output_headers, "Host", host);
    header.push_back("Content-Type: application/json");
    header.push_back("Connection: close");

    request.setOpt(new curlpp::options::HttpHeader(header));

    UniValue jsonRequest=JSONRPCRequestObj(strMethod, params, 1);
    jsonRequest.push_front(Pair("jsonrpc","2.0"));
    std::string strRequest = jsonRequest.write() + "\n";

    request.setOpt(new curlpp::options::PostFields(strRequest));
    request.setOpt(new curlpp::options::PostFieldSize(strRequest.length()));

    std::ostringstream response;
    request.setOpt(new curlpp::options::WriteStream(&response));

    request.perform();

    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.str())){
            throw std::runtime_error("couldn't parse reply from server");
    }
    const UniValue& reply = valReply.get_obj();
    if (reply.empty()){
        throw std::runtime_error("expected reply to have result, error and id properties");
    }

    return reply;
}



