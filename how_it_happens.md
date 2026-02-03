Main thread {
evluaserver.main (T0)
    Instantiates EVFormRequestHandlerFactory which has impl of createRequestHandler
    Instantiates EVHTTPServer,
        the construcor instantiates EVTCPServer(new EVHTTPRequestProcessorFactory(pParams, EVFormRequestHandlerFactory), ...)
            EVTCPServer::pFactory = EVHTTPRequestProcessorFactory
                EVHTTPRequestProcessorFactory has createConnection, which instantiates EVHTTPRequestProcessor
                EVHTTPRequestProcessorFactory has createReqProcState, which instantiates EVHTTPProcessingState
            \_pConnectionFactory = EVTCPServerConnectionFactory(pFactory) = EVHTTPRequestProcessorFactory
            starts thread pool
            pDispatcher = EVTCPServerDispatcher(pFactory, thread pool, ...) Dispatcher is a running thread
                \_pConnectionFactory = pFactory = EVHTTPRequestProcessorFactory
    Starts the server
}

Event Listener thread {
which eventually starts at EVTCPServer.run and the server starts ...  (T1)
... New connection handling etc. happens ...
Upon new request the EVTCPServer
    Creates new processing state \_pConnectionFactory-\>createReqProcState(this) this results in EVHTTPProcessingState
    sets it in accetped socket (tn)
    ...
    justEnqueue(tn), which enqueues the tn to Dispatcher Starts a Dispatcher thread lazily. No usN (initial)

Upon an upstream notification event (e.g. database read complete, file read complete)
    adds the usN to the event queue
    justEnqueue(tn). With usN (continuation)
}

Worker threads [{
The run of dispatcher notices a tn on the queue (Thread pool T3 ..... TN)
    pConnection(\_pConnectionFactory-\>createConnection(pCNf-\>socket()-\>getStreamSocket()));           
    => EVHTTPRequestProcessorFactory.createConnection(socket = accepted socjet leads to EVHTTPRequestProcessor which is an EVTCPServerConnection
        results in EVTCPServerConnection(EVHTTPRequestProcessor) this is deleted after one run in dispatcher (unique ptr)
    set the processing state which was set in TCP server into the pConnection
    set other things, eevent queue, req and res mem streams
    pConnection-\>start() => pConnection-\>run() => EVHTTPRequestProcessor::run()
        Reads HTTP Request
        Creates Request handler and stores it in EVHTTPProcessingState if it is not already created. Here pFactory is EVFormRequestHandlerFactory of evluaserver which creates an instance of EVLHTTPRequestHandler
        created now => initial request , handles the request
        created earlier => continuation of the existing request
            picks up the usN from event queue (THIS IS OUR POTENTIAL MEMORY OVERWRITE POINT)
            Continues execution on EVHTTPRequestHandler and thus EVLHTTPRequestHandler
}]



            


    

