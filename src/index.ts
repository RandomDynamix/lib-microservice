"use strict";
const base64url         = require("base64url");
const EventEmitter      = require("events");
const jwt               = require("jsonwebtoken");
const { NATSClient }    = require("@randomrod/lib-nats-client");
const uuid              = require("uuid");

const CLIENT_PREFIX = 'CLIENT';

export class Microservice extends NATSClient {
    messageValidator: any = {
        privateKey: process.env.JWT_PRIVATE_KEY || null,
        publicKey:  process.env.JWT_PUBLIC_KEY  || null,
        algorithm:  process.env.JWT_ALGORITHM   || null
    };

    constructor(public serviceName: string) {
        super(serviceName);
    }

    async init() {
        await super.init();
        if(!this.messageValidator.privateKey) {
            try{this.emit('info', 'no correlation', 'Message Signing NOT Configured');}catch(err){}
        }
        if(!this.messageValidator.publicKey) {
            try{this.emit('info', 'no correlation', 'Message Validation NOT Configured');}catch(err){}
        }
        this.registerTestHandlers();
    }

    async queryTopic(topic: string, context: any, payload: any, timeoutOverride?: number, topicPrefixOverride?: string) {
        if(typeof context !== 'object' || typeof payload !== 'object')
            throw 'INVALID REQUEST: One or more of context or payload are not properly structured objects.';

        //Reset the Context to remove previously decoded information (keep it clean!)
        let newContext: any = {
            correlationUUID: context.correlationUUID ? context.correlationUUID : 'MICROSERVICE'
        };
        if(context.idToken) newContext.idToken = context.idToken;
        if(context.serviceToken) newContext.serviceToken = context.serviceToken;
        if(context.impersonationToken) newContext.impersonationToken = context.impersonationToken;
        if(context.ephemeralToken) newContext.ephemeralToken = context.ephemeralToken;

        let queryData = {
            context: newContext,
            payload
        };

        let stringQueryData = JSON.stringify(queryData);
        try{this.emit('debug', newContext.correlationUUID, `NATS REQUEST (${topic}): ${stringQueryData}`);}catch(err){}

        let queryResponse = null;
        if(timeoutOverride) queryResponse = await super.queryTopic(`${topicPrefixOverride ? topicPrefixOverride : CLIENT_PREFIX}.${topic}`, stringQueryData, timeoutOverride);
        else queryResponse = await super.queryTopic(`${topicPrefixOverride ? topicPrefixOverride : CLIENT_PREFIX}.${topic}`, stringQueryData);

        if(!queryResponse) throw `INVALID RESPONSE (${topic}) from NATS Mesh`;

        try{this.emit('debug', newContext.correlationUUID, `NATS RESPONSE (${topic}): ${queryResponse}`);}catch(err){}
        let parsedResponse = JSON.parse(queryResponse);

        if(parsedResponse.response.errors) throw parsedResponse.response.errors;
        return parsedResponse.response.result;
    }

    publishEvent(topic: string, context: any, payload: any, topicPrefixOverride?: string) {
        if(typeof context !== 'object' || typeof payload !== 'object')
            throw 'INVALID REQUEST: One or more of context or payload are not properly structured objects.';

        let eventData = {
            context,
            payload
        };

        let stringEventData = JSON.stringify(eventData);
        try{this.emit('debug', 'no correlation', `NATS PUBLISH (${topic}): ${stringEventData}`);}catch(err){}

        return super.publishTopic(`${topicPrefixOverride ? topicPrefixOverride : CLIENT_PREFIX}.${topic}`, stringEventData);
    }

    registerTopicHandler(topic: string, fnHandler: any, queue: any = null, topicPrefixOverride?: string) {
        try {
            let topicHandler = async (request: string, replyTo: string, topic: string) => {
                let errors = null;
                let result = null;
                let topicStart = Date.now();

                try {
                    try{this.emit('debug', 'SERVICE', 'Microservice | TopicHandler (' + topic + ') | ' + request);}catch(err){}

                    let parsedRequest = request ? JSON.parse(request) : null;
                    if(!parsedRequest.context || !parsedRequest.payload )
                        throw 'INVALID REQUEST: Either context or payload, or both, are missing.';

                    //Verify MESSAGE AUTHORIZATION
                    parsedRequest.context.assertions = this.validateRequest(topic, parsedRequest.context);
                    parsedRequest.context.topic = topic.substring(topic.indexOf(".")+1);

                    //Request is Valid, Handle the Request
                    result = await fnHandler(parsedRequest);
                    if(typeof result !== 'object') {
                        result = {
                            status: result
                        };
                    } else if (result === {}) {
                        result = {
                            status: "SUCCESS"
                        }
                    }

                } catch(err) {
                    let error = `Service Error(${fnHandler.name.substring(6)}): ${JSON.stringify(err)}`;
                    try{this.emit('error', 'SERVICE', error);}catch(err){}
                    if(!errors) errors = [err];
                }

                let topicDuration = Date.now() - topicStart;

                if(replyTo) {
                    this.publishResponse(replyTo, errors, result);
                    try{this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + topicDuration.toString() + 'ms | ' + JSON.stringify(errors ? errors : result));}catch(err){}
                } else {
                    try{this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + topicDuration.toString() + 'ms | No Response Requested');}catch(err){}
                }
            };

            super.registerTopicHandler(`${topicPrefixOverride ? topicPrefixOverride : 'MESH'}.${topic}`, topicHandler, queue);

        } catch(err) {
            try{this.emit('error', 'SERVICE', 'Microservice | registerTopicHandler (' + topic + ') Error: ' + err);}catch(err){}
        }
    }

    generateToken(assertions: any) {
        try {
            if(!this.messageValidator.privateKey || !this.messageValidator.algorithm) throw "MessageValidator Not Configured";
            return jwt.sign(assertions, this.messageValidator.privateKey, {algorithm: this.messageValidator.algorithm});
        } catch(err) {
            try{this.emit('error', 'MICROSERVICE', `Error Generating Ephemeral Token: ${JSON.stringify(err)}`);}catch(err){}
        }
    }

    verifyToken(token: any) {
        try {
            if(!this.messageValidator.publicKey || !this.messageValidator.algorithm) throw "MessageValidator Not Configured";
            return jwt.verify(token, this.messageValidator.publicKey, {algorithms: [this.messageValidator.algorithm]});
        } catch(err) {
            try{this.emit('error', 'MICROSERVICE', `Error Verifying Ephemeral Token: ${JSON.stringify(err)}`);}catch(err){}
        }
    }

    decodeToken(token: any) {
        try {
            let decoded: any = jwt.decode(token, {complete: true});
            return decoded.payload;
        } catch(err) {
            try{this.emit('error', 'MICROSERVICE', `Error Decoding Ephemeral Token: ${JSON.stringify(err)}`);}catch(err){}
        }
    }

    //PRIVATE FUNCTIONS
    private validateRequest(topic: string, context: any) {

        if(!context.ephemeralToken && !topic.endsWith("NOAUTH"))// && !topic.endsWith("INTERNAL"))
            throw 'UNAUTHORIZED: Ephemeral Authorization Token Missing';

        if(!context.ephemeralToken) return {};

        let token_assertions = null;
        try {
            token_assertions = (this.messageValidator.publicKey && this.messageValidator.algorithm)
                ? this.verifyToken(context.ephemeralToken)
                : this.decodeToken(context.ephemeralToken);

            if(!token_assertions)                 throw "Error Decoding Ephemeral Authorization Token";
            if(token_assertions.exp < Date.now()) throw "Ephemeral Authorization Token Expired";

            if(!token_assertions.ephemeralAuth) throw "Invalid Ephemeral Authorization Token";
            let ephemeralAuth = JSON.parse(base64url.decode(token_assertions.ephemeralAuth));

            if(!ephemeralAuth.authentication || !ephemeralAuth.authorization) throw "Invalid Ephemeral Authorization Token Payload";
            if(!ephemeralAuth.authorization.superAdmin && topic.endsWith("RESTRICTED")) throw "SCOPE VIOLATION: Requires SuperAdmin Access";

            token_assertions.authentication = ephemeralAuth.authentication;
            token_assertions.authorization = ephemeralAuth.authorization;

        } catch(err) {
            throw `UNAUTHORIZED: validateRequest Error: ${JSON.stringify(err)}`;
        }
        return token_assertions;
    }

    private publishResponse(replyTopic: string, errors: any, result: any) {
        let response = JSON.stringify({
            response: {
                errors: errors,
                result: result
            }
        });
        return super.publishTopic(replyTopic, response);
    }

    //***************************************************
    // TOPOLOGY TEST Functions
    //***************************************************
    async scanToplogy(request: any) {
        if(!request.payload.testID) throw 'No Test ID specified';
        if(!request.payload.nodes)  throw 'No Test Nodes specified';

        let scanResult: any = {
            testStart: Date.now(),
        };

        let nodeResults: any[] = [];
        let testRequest = JSON.stringify({ context: request.context, payload: { testID: request.payload.testID }});
        for(let node of request.payload.nodes) {

            let nodeStart = Date.now();
            let nodeResult: any = { node };
            let queryResponse = await super.queryTopic(`TEST.${node}.ping.validate`, testRequest, 100);

            nodeResult.duration = Date.now() - nodeStart;
            if(!queryResponse) {
                nodeResult.result = `NO RESPONSE`;
            } else {
                let parsedResponse = JSON.parse(queryResponse);
                if(parsedResponse.response.errors) {
                    let errorString = JSON.stringify(parsedResponse.response.errors);
                    if(errorString.indexOf('TIMEOUT') >= 0)
                        nodeResult.result = 'TIMEOUT';
                    else
                        nodeResult.result = `${errorString}`;
                } else if(!parsedResponse.response.result) {
                    nodeResult.result = 'NO RESULT';
                } else {
                    if(parsedResponse.response.result.testID = request.payload.testID)
                        nodeResult.result = 'OK';
                    else
                        nodeResult.result = 'UNCORRELATED';
                }
            }
            nodeResults.push(nodeResult);
        }

        scanResult.testEnd = Date.now();
        scanResult.duration = scanResult.testEnd - scanResult.testStart;
        scanResult.nodeResults = nodeResults;
        return scanResult;
    }

    async validateNode(request: any) {
        return { testID: request.payload.testID };
    }

    private registerTestHandlers() {
        let instanceID = uuid.v4();
        let initiatorTopic = `TEST.${this.serviceName}.${instanceID}.ping.initiate`;
        this.registerTestHandler(initiatorTopic, this.scanToplogy.bind(this), instanceID);

        let validatorTopic = `TEST.${this.serviceName}.${instanceID}.ping.validate`;
        this.registerTestHandler(validatorTopic, this.validateNode.bind(this), instanceID);
    }

    private registerTestHandler(topic: string, fnHandler: any, queue: any = null) {
        try {
            let topicHandler = async (request: string, replyTo: string, topic: string) => {
                let errors = null;
                let result = null;
                let topicStart = Date.now();

                try {
                    try{this.emit('debug', 'SERVICE TEST', 'Microservice | TopicHandler (' + topic + ') | ' + request);}catch(err){}

                    let parsedRequest = request ? JSON.parse(request) : null;
                    if(!parsedRequest.context || !parsedRequest.payload )
                        throw 'INVALID REQUEST: Either context or payload, or both, are missing.';

                    result = await fnHandler(parsedRequest);

                } catch(err) {
                    let error = `Test Error(${topic}): ${JSON.stringify(err)}`;
                    try{this.emit('error', 'SERVICE TEST', error);}catch(err){}
                    if(!errors) errors = [err];
                }

                let topicDuration = Date.now() - topicStart;

                if(replyTo) {
                    this.publishResponse(replyTo, errors, result);
                    try{this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + topicDuration.toString() + 'ms | ' + JSON.stringify(errors ? errors : result));}catch(err){}
                } else {
                    try{this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + topicDuration.toString() + 'ms | No Response Requested');}catch(err){}
                }
            };

            super.registerTopicHandler(topic, topicHandler, queue);

        } catch(err) {
            try{this.emit('error', 'SERVICE TEST', 'Microservice | registerTopicHandler (' + topic + ') Error: ' + err);}catch(err){}
        }
    }

}