import { NATSClient, NATSTopicHandler }     from '@randomrod/lib-nats-client';
import base64url                            from 'base64url';
import jwt, {Jwt, JwtPayload, Algorithm}         from 'jsonwebtoken';
import { v4 as uuidv4 }                     from 'uuid';

const INTERNAL_PREFIX = 'INTERNAL';
const MESH_PREFIX     = 'MESH';

const SUPERADMIN    = 'SUPERADMIN';
const QUERY_TIMEOUT = 7500;

interface JWTValidator {
    privateKey: string | null,
    publicKey:  string | null,
    jwtAlgorithm: Algorithm
}

export interface ServiceRequest {
    context: any,
    payload: any
}

export interface ServiceHandler {
    (request: ServiceRequest): Promise<any>;
}

export interface ScopeRestriction {
    site_id?:   string,
    member_id?: string,
    user_id?:   string
}

export class Microservice extends NATSClient {
    sourceVersion: string = process.env.SOURCE_VERSION  || 'LOCAL';
    messageValidator: JWTValidator = {
        privateKey:         process.env.JWT_PRIVATE_KEY ||  null,
        publicKey:          process.env.JWT_PUBLIC_KEY  ||  null,
        jwtAlgorithm:      (process.env.JWT_ALGORITHM   || 'RS256') as Algorithm,
    };

    serviceMessages: string[] = [];

    constructor(serviceName: string) {
        super(serviceName);
    }

    async init(): Promise<void> {
        await super.init();
        if(!this.messageValidator.privateKey)
            try{this.emit('info', 'no correlation', 'Message Signing NOT Configured');}catch(err){}

        if(!this.messageValidator.publicKey)
            try{this.emit('info', 'no correlation', 'Message Validation NOT Configured');}catch(err){}

        this.registerTestHandler();
    }

    async query(topic: string, context: any, payload: any, queryTimeout: number = QUERY_TIMEOUT, topicPrefix: string = INTERNAL_PREFIX): Promise<any> {
        if(typeof context !== 'object' || typeof payload !== 'object')
            throw 'INVALID REQUEST: One or more of context or payload are not properly structured objects.';

        //Reset the Context to remove previously decoded information (keep it clean!)
        let newContext: any = {
            correlationUUID:    context.correlationUUID     || uuidv4(),
            siteID:             context.siteID              || null,
            idToken:            context.idToken             || null,
            ephemeralToken:     context.ephemeralToken      || null,
        };

        let queryData = JSON.stringify({ context: newContext, payload });
        try{this.emit('debug', newContext.correlationUUID, `NATS REQUEST (${topic}): ${queryData}`);}catch(err){}

        let topicStart = Date.now();

        let queryResponse: string = await super.queryTopic(`${topicPrefix}.${topic}`, queryData, queryTimeout);
        if(!queryResponse) throw `INVALID RESPONSE (${topic}) from NATS Mesh`;

        let topicDuration = Date.now() - topicStart;

        try{this.emit('info', newContext.correlationUUID, `NATS RESPONSE (${topic}) | ${topicDuration} ms`);}catch(err){}
        try{this.emit('debug', newContext.correlationUUID, `NATS RESPONSE (${topic}) | ${topicDuration} ms : ${queryResponse}`);}catch(err){}

        let parsedResponse = JSON.parse(queryResponse);
        if(parsedResponse.response.errors) throw parsedResponse.response.errors;
        return parsedResponse.response.result;
    }

    publish(topic: string, context: any, payload: any, topicPrefix: string = INTERNAL_PREFIX): void {
        if(typeof context !== 'object' || typeof payload !== 'object')
            throw 'INVALID REQUEST: One or more of context or payload are not properly structured objects.';

        let eventData = JSON.stringify({ context, payload });
        try{this.emit('debug', 'no correlation', `NATS PUBLISH (${topic}): ${eventData}`);}catch(err){}

        return super.publishTopic(`${topicPrefix}.${topic}`, eventData);
    }

    registerHandler(topic: string, fnHandler: ServiceHandler, minScopeRequired: string = SUPERADMIN, queue: string | null = null, topicPrefix: string = MESH_PREFIX): void {
        try {
            this.serviceMessages.push(topic);
            let topicHandler: NATSTopicHandler = async (request: string, replyTo: string, topic: string): Promise<void> => {
                let errors = null;
                let result = null;
                let topicStart = Date.now();

                try {
                    try{this.emit('debug', 'SERVICE', 'Microservice | TopicHandler (' + topic + ') | ' + request);}catch(err){}

                    let parsedRequest: ServiceRequest = request ? JSON.parse(request) : null;
                    if(!parsedRequest?.context || !parsedRequest?.payload )
                        throw 'INVALID REQUEST: Either context or payload, or both, are missing.';

                    //Verify MESSAGE AUTHORIZATION
                    parsedRequest.context.assertions = await this.validateRequestAssertions(topic, parsedRequest.context, minScopeRequired);
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
                    try{this.emit('info', 'SERVICE', `Microservice | topicHandler (${topic}) | ${topicDuration} ms`);}catch(err){}
                    try{this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + topicDuration.toString() + 'ms | ' + JSON.stringify(errors ? errors : result));}catch(err){}
                } else {
                    try{this.emit('info', 'SERVICE', `Microservice | topicHandler (${topic}) | ${topicDuration} ms`);}catch(err){}
                    try{this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + topicDuration.toString() + 'ms | No Response Requested');}catch(err){}
                }
            };

            super.registerTopicHandler(`${topicPrefix}.${topic}`, topicHandler, queue);

        } catch(err) {
            try{this.emit('error', 'SERVICE', 'Microservice | registerTopicHandler (' + topic + ') Error: ' + err);}catch(err){}
        }
    }

    async generateToken(assertions: any): Promise<string | null> {
        try {
            if(!this.messageValidator.privateKey || !this.messageValidator.jwtAlgorithm) throw "MessageValidator Not Configured";
            return jwt.sign(assertions, this.messageValidator.privateKey, {algorithm: this.messageValidator.jwtAlgorithm});
        } catch(err) {
            try{this.emit('error', 'MICROSERVICE', `Error Generating Ephemeral Token: ${JSON.stringify(err)}`);}catch(err){}
        }
        return null;
    }

    async verifyToken(token: any): Promise<JwtPayload | string | null> {
        try {
            if(!this.messageValidator.publicKey || !this.messageValidator.jwtAlgorithm) throw "MessageValidator Not Configured";
            return jwt.verify(token, this.messageValidator.publicKey, {algorithms: [this.messageValidator.jwtAlgorithm]});
        } catch(err) {
            try{this.emit('error', 'MICROSERVICE', `Error Verifying Ephemeral Token: ${JSON.stringify(err)}`);}catch(err){}
        }
        return null;
    }

    decodeToken(token: any): JwtPayload | null {
        try {
            let decoded: Jwt | null = jwt.decode(token, {complete: true});
            if(decoded?.payload) return decoded.payload;
        } catch(err) {
            try{this.emit('error', 'MICROSERVICE', `Error Decoding Ephemeral Token: ${JSON.stringify(err)}`);}catch(err){}
        }
        return null;
    }

    verifyParameters(test: any, fields: string[]): void {
        if(!test) throw 'VALIDATION: Missing Verification Test Object';

        for(let field of fields) {
            let fieldEntries = field.split(",");
            if(fieldEntries.length > 1) {
                let anyFound = false;
                for(let fieldEntry of fieldEntries) {
                    if(test.hasOwnProperty(fieldEntry) && test[field] !== null) anyFound = true;
                }
                if(!anyFound)  throw `VALIDATION: Missing At Least One Parameter Of - ${field}`;
            } else {
                if(!test.hasOwnProperty(field) || test[field] === null )
                    throw `VALIDATION: Missing Parameter - ${field}`;
            }
        }
    }

    //PRIVATE FUNCTIONS
    private async validateRequestAssertions(topic: string, context: any, minScopeRequired: string): Promise<any> {

        if(!context.ephemeralToken && minScopeRequired !== 'NOAUTH') throw 'UNAUTHORIZED: Ephemeral Authorization Token Missing';
        if(!context.ephemeralToken) return null;

        let token_assertions: any = null;
        try {
            if(this.messageValidator.publicKey && this.messageValidator.jwtAlgorithm) {
                token_assertions = await this.verifyToken(context.ephemeralToken);
                if(token_assertions) token_assertions.signatureVerified = true;
            } else {
                token_assertions = this.decodeToken(context.ephemeralToken);
                if(token_assertions) token_assertions.signatureVerified = false;
            }

            if(!token_assertions)                 throw "Error Decoding Ephemeral Authorization Token";
            if(token_assertions.exp < Date.now()) throw "Ephemeral Authorization Token Expired";

            if(!token_assertions.ephemeralAuth) throw "Invalid Ephemeral Authorization Token";
            let ephemeralAuth = JSON.parse(base64url.decode(token_assertions.ephemeralAuth));

            if(!ephemeralAuth.authentication || !ephemeralAuth.authorization) throw "Invalid Ephemeral Authorization Token Payload";

            token_assertions.authentication = ephemeralAuth.authentication;
            token_assertions.authorization = ephemeralAuth.authorization;

            token_assertions.authorization.scope = (topic: string) => {
                if(topic.endsWith('INTERNAL'))                return '*';
                if(token_assertions.authorization.superAdmin) return '*';
                return token_assertions.authorization.permissions[topic] || 'NONE';
            };

            let assertedScope: string = token_assertions.authorization.scope(topic);
            token_assertions.authorization.scopeRestriction = this.authorizeScope(assertedScope, token_assertions, minScopeRequired);

        } catch(err) {
            throw `UNAUTHORIZED: validateRequestAssertions Error: ${JSON.stringify(err)}`;
        }
        return token_assertions;
    }

    private authorizeScope(assertedScope: string, assertions: any, minScopeRequired: string): ScopeRestriction | null {

        if(assertions.authorization.superAdmin) return null;

        switch(minScopeRequired) {
            case '*':
                if(assertedScope !== '*')  throw 'UNAUTHORIZED:  Requires GLOBAL Permission Scope';
                break;

            case 'SITE':
                if( assertedScope !== '*' &&
                    assertedScope !== 'SITE')  throw 'UNAUTHORIZED:  Requires SITE Permission Scope or Greater';
                break;

            case 'MEMBER':
                if( assertedScope !== '*' &&
                    assertedScope !== 'SITE' &&
                    assertedScope !== 'MEMBER')  throw 'UNAUTHORIZED:  Requires MEMBER Permission Scope or Greater';
                break;

            case 'OWNER':
                if( assertedScope !== '*' &&
                    assertedScope !== 'SITE' &&
                    assertedScope !== 'MEMBER' &&
                    assertedScope !== 'OWNER')  throw 'UNAUTHORIZED:  Requires OWNER Permission Scope or Greater';
                break;

            case 'NOAUTH':
                return null; //Shortcut - no scope check, no restrictions
                break;

            default:
                throw `SERVER ERROR:  Invalid Scope Requirement (${minScopeRequired})`;
        }

        //Default to OWNER (lowest) Scope
        let scopeRestriction: ScopeRestriction | null = { user_id: assertions.authentication.user_id };
        switch(assertedScope) {
            case "MEMBER":
                scopeRestriction = { member_id: assertions.authentication.member_id };
                break;

            case "SITE":
                scopeRestriction = { site_id: assertions.authentication.site_id };
                break;

            case "*":
                scopeRestriction = null;
        }
        return scopeRestriction;
    }

    private publishResponse(replyTopic: string, errors: any, result: any): void {
        let response = JSON.stringify({
            response: {
                errors: errors,
                result: result
            }
        });
        return super.publishTopic(replyTopic, response);
    }

    //***************************************************
    // TEST Function
    //***************************************************
    private versionNode() {
        return { version: this.sourceVersion, messages: this.serviceMessages };
    }

    private registerTestHandler() {
        let instanceID: string = uuidv4();
        let testTopic: string = `TEST.${this.serviceName}.${instanceID}`;

        try {
            let topicHandler: NATSTopicHandler = async (request: string, replyTo: string, topic: string): Promise<void> => {
                let errors = null;
                let result = null;

                try {
                    try{this.emit('debug', 'SERVICE TEST', 'Microservice | TopicHandler (' + topic + ') | ' + request);}catch(err){}

                    let parsedRequest: ServiceRequest = request ? JSON.parse(request) : null;
                    if(!parsedRequest) throw 'INVALID REQUEST: Either context or payload, or both, are missing.';

                    result = this.versionNode();

                } catch(err) {
                    let error = `Test Error(${topic}): ${JSON.stringify(err)}`;
                    try{this.emit('error', 'SERVICE TEST', error);}catch(err){}
                    if(!errors) errors = [err];
                }

                if(replyTo) {
                    this.publishResponse(replyTo, errors, result);
                    try{this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + JSON.stringify(errors ? errors : result));}catch(err){}
                } else {
                    try{this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | No Response Requested');}catch(err){}
                }
            };

            super.registerTopicHandler(testTopic, topicHandler, instanceID);

        } catch(err) {
            try{this.emit('error', 'SERVICE TEST', 'Microservice | registerTopicHandler (' + testTopic + ') Error: ' + err);}catch(err){}
        }
    }

}