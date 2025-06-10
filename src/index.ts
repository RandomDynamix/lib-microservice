import { NATSClient, NATSTopicHandler }     from '@randomrod/lib-nats-client';
import base64url                            from 'base64url';
import jwt, {Jwt, JwtPayload, Algorithm}    from 'jsonwebtoken';
import { v4 as uuidv4 }                     from 'uuid';

const DOMAIN_INTERNAL = 'INTERNAL';
const INTERNAL_PREFIX = 'INTERNAL';
const MESH_PREFIX     = 'MESH';

const SUPERADMIN    = 'SUPERADMIN';
const QUERY_TIMEOUT = 7500;

interface JWTValidator {
    publicPEM?:    string | null,
    jwtAlgorithm?: Algorithm
}

export interface ServiceRequest {
    context: any,
    payload: any
}

export interface ServiceHandler {
    (request: ServiceRequest): Promise<any>;
}

export interface ScopeRestriction {
    site_authorized?:   any,
    site_access_id?:    string,
    site_id?:           string,
    member_id?:         string,
    user_id?:           string,
    entity_id?:         string
}

export class Microservice extends NATSClient {
    sourceVersion: string = process.env.SOURCE_VERSION  || 'LOCAL';
    jwtValidator: JWTValidator = {
        publicPEM:          process.env.JWT_MESH_PUBLIC_PEM ? Buffer.from(process.env.JWT_MESH_PUBLIC_PEM, 'base64').toString('ascii')  :  null,
        jwtAlgorithm:      (process.env.JWT_ALGORITHM   || 'RS256') as Algorithm,
    };

    serviceMessages: string[] = [];

    constructor(serviceName: string) {
        super(serviceName);
    }

    async init(): Promise<void> {
        await super.init();

        if(!this.jwtValidator.publicPEM)
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
            apiKey:             context.apiKey              || null,
            ephemeralToken:     context.ephemeralToken      || null,
            proxyToken:         context.proxyToken          || null,
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

    registerHandler(handlerTopic: string, fnHandler: ServiceHandler, minScopeRequired: string = SUPERADMIN, queue: string | null = null, topicPrefix: string = MESH_PREFIX): void {
        try {
            this.serviceMessages.push(handlerTopic);
            let topicHandler: NATSTopicHandler = async (request: string, replyTo: string, topic: string): Promise<void> => {
                let errors = null;
                let result = null;
                let topicStart = Date.now();
                topic = topic.substring(topic.indexOf(".")+1);  //Strip the Prefix

                try {
                    try{this.emit('debug', 'SERVICE', 'Microservice | TopicHandler (' + topic + ') | ' + request);}catch(err){}

                    let parsedRequest: ServiceRequest = request ? JSON.parse(request) : null;
                    if(!parsedRequest?.context || !parsedRequest?.payload )
                        throw 'INVALID REQUEST: Either context or payload, or both, are missing.';

                    //Verify MESSAGE AUTHORIZATION
                    parsedRequest.context.assertions = await this.validateRequestAssertions(topic, parsedRequest.context, minScopeRequired);
                    parsedRequest.context.topic = topic;

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

            super.registerTopicHandler(`${topicPrefix}.${handlerTopic}`, topicHandler, queue);

        } catch(err) {
            try{this.emit('error', 'SERVICE', 'Microservice | registerTopicHandler (' + handlerTopic + ') Error: ' + err);}catch(err){}
        }
    }

    verifyToken(token: string, publicPEM?: string, algorithm?: Algorithm): JwtPayload | string | null {
        try {
            let verificationPEM: string | null     = publicPEM || this.jwtValidator.publicPEM || null;
            let verificationAlgo: Algorithm | null = algorithm || this.jwtValidator.jwtAlgorithm || null;

            if(!verificationPEM || !verificationAlgo) throw "JWTValidator Not Configured";
            return jwt.verify(token, <string>verificationPEM, {algorithms: [verificationAlgo]});
        } catch(err) {
            try{this.emit('error', 'MICROSERVICE', `Error Verifying Token: ${JSON.stringify(err)}`);}catch(err){}
        }
        return null;
    }

    decodeToken(token: string): JwtPayload | string | null {
        try {
            let decoded: Jwt | string | null = jwt.decode(token, {complete: true});
            if(decoded?.payload) return decoded.payload;
        } catch(err) {
            try{this.emit('error', 'MICROSERVICE', `Error Decoding Token: ${JSON.stringify(err)}`);}catch(err){}
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
            //Process ephemeralToken First
            let ephemeral_assertions: any = null;
            if(this.jwtValidator.publicPEM && this.jwtValidator.jwtAlgorithm) {
                ephemeral_assertions = await this.verifyToken(context.ephemeralToken);
                if(ephemeral_assertions) ephemeral_assertions.signatureVerified = true;
            } else {
                ephemeral_assertions = this.decodeToken(context.ephemeralToken);
                if(ephemeral_assertions) ephemeral_assertions.signatureVerified = false;
            }

            if(!ephemeral_assertions)                 throw "Error Decoding Ephemeral Authorization Token";
            if(!ephemeral_assertions.exp)             throw "Invalid Ephemeral Authorization Token: Missing exp";
            if(ephemeral_assertions.exp < Date.now()) throw "Ephemeral Authorization Token Expired";

            let requestDomain: string = ephemeral_assertions.domain || DOMAIN_INTERNAL;

            if(!ephemeral_assertions.ephemeralAuth)   throw "Invalid Ephemeral Authorization Token: Missing ephemeralAuth";
            let ephemeralAuth = JSON.parse(base64url.decode(ephemeral_assertions.ephemeralAuth));

            if(!ephemeralAuth.authentication || !ephemeralAuth.authorization) throw "Invalid Ephemeral Authorization Token Payload";

            let requestAuthentication: any = ephemeralAuth.authentication;
            let requestAuthorization: any = ephemeralAuth.authorization;
            let signatureVerified: boolean = ephemeral_assertions.signatureVerified;

            //Process proxyToken (if exists) Second
            if(context.proxyToken) {
                let proxy_assertions: any = null;
                if(this.jwtValidator.publicPEM && this.jwtValidator.jwtAlgorithm) {
                    proxy_assertions = await this.verifyToken(context.proxyToken);
                } else {
                    proxy_assertions = this.decodeToken(context.proxyToken);
                }

                if(!proxy_assertions)                 throw "Error Decoding Proxy Authorization Token";
                if(!proxy_assertions.exp)             throw "Invalid Proxy Authorization Token: Missing exp";
                if(proxy_assertions.exp < Date.now()) throw "Proxy Authorization Token Expired";

                if(!proxy_assertions.ephemeralAuth)   throw "Invalid Proxy Authorization Token: Missing ephemeralAuth";
                let proxyAuth = JSON.parse(base64url.decode(proxy_assertions.ephemeralAuth));

                if(!proxyAuth.authentication || !proxyAuth.authorization) throw "Invalid Proxy Authorization Token Payload";

                requestAuthentication.proxy = proxyAuth.authentication;
                requestAuthorization = this.proxyAuthorization(requestAuthorization, proxyAuth.authorization);
                requestDomain = DOMAIN_INTERNAL;
            }

            token_assertions = {
                authentication: requestAuthentication,
                authorization: requestAuthorization,
                domain: requestDomain,
                signatureVerified: signatureVerified
            };

            token_assertions.authorization.scope = (topic: string) => {
                if(token_assertions.authorization.superAdmin) return '*';
                return token_assertions.authorization.permissions[topic] || 'NONE';
            };

            let assertedScope: string = token_assertions.authorization.scope(topic);
            token_assertions.authorization.scopeRestriction = this.authorizeScope(assertedScope, token_assertions, minScopeRequired);

            token_assertions.authorization.siteScopeAuthorized = (site_id: string) => {
                let scopeRestriction = token_assertions.authorization.scopeRestriction;
                if(!scopeRestriction) return true;
                if(scopeRestriction.site_access) {
                    for(let site_access_site_id of scopeRestriction.site_access) {
                        if(site_access_site_id === site_id) return true;
                    }
                }
                return false;
            };

        } catch(err) {
            throw `UNAUTHORIZED: validateRequestAssertions Error: ${JSON.stringify(err)}`;
        }
        return token_assertions;
    }

    private proxyAuthorization(baseAuthorization: any, proxyAuthorization: any): any {
        //This merges the two authorizations, taking the HIGHEST authorization, if there is overlap
        if(baseAuthorization.superAdmin) return baseAuthorization;
        if(proxyAuthorization.superAdmin) {
            baseAuthorization.superAdmin = true;
            baseAuthorization.roleLevel = proxyAuthorization.roleLevel;
            return baseAuthorization;
        }

        //Otherwise, iterate permissions
        for(let permission in proxyAuthorization.permissions) {
            let basePermission: string     = baseAuthorization.permissions[permission];
            let proxyPermission: string = proxyAuthorization.permissions[permission];

            if(!basePermission) baseAuthorization.permissions[permission] = proxyPermission;
            else {
                switch(basePermission) {
                    case "ENTITY":
                        if (proxyPermission !== "ENTITY") {
                            baseAuthorization.permissions[permission] = proxyPermission;
                        }
                        break;

                    case "OWNER":
                        if (proxyPermission !== "OWNER" && proxyPermission !== "ENTITY") {
                            baseAuthorization.permissions[permission] = proxyPermission;
                        }
                        break;

                    case "MEMBER":
                        if (proxyPermission === "*" || proxyPermission === "SITE") {  //Only change if a higher privilege
                            baseAuthorization.permissions[permission] = proxyPermission
                        }
                        break;

                    case "SITE":
                        if (proxyPermission === "*") {  //Only change if a higher privilege
                            baseAuthorization.permissions[permission] = proxyPermission
                        }
                        break;

                    case "*":
                        //Do Nothing - already have the highest privilege
                        break;
                }
            }
        }

        //Use the highest role level
        if(proxyAuthorization.roleLevel > baseAuthorization.roleLevel)
            baseAuthorization.roleLevel = proxyAuthorization.roleLevel;

        return baseAuthorization;
    }

    private authorizeScope(assertedScope: string, assertions: any, minScopeRequired: string): ScopeRestriction | null {

        if(assertions.authorization.superAdmin) return null;

        switch(minScopeRequired) {
            case 'SUPERADMIN':
                if(!assertions.authorization.superAdmin) throw 'UNAUTHORIZED: Requires SUPERADMIN Permissions';
                break;

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

            case 'ENTITY':
                if( assertedScope !== '*' &&
                    assertedScope !== 'SITE' &&
                    assertedScope !== 'MEMBER' &&
                    assertedScope !== 'OWNER' &&
                    assertedScope !== 'ENTITY')  throw 'UNAUTHORIZED:  Requires ENTITY Permission Scope or Greater';
                break;

            case 'NOAUTH':
                return null; //Shortcut - no scope check, no restrictions
                break;

            default:
                throw `SERVER ERROR:  Invalid Scope Requirement (${minScopeRequired})`;
        }

        //Default to OWNER Scope
        //NOTE: A "new" scope has been introduced, called ENTITY, which is now the "lowest" scope; however,
        //      it is a "special case" override to the OWNER scope (for external users).  Thus, it is NOT the default.
        let scopeRestriction: ScopeRestriction | null = { user_id: assertions.authentication.user_id };
        switch(assertedScope) {
            case "ENTITY":          //NOTE:  uuidv4() is a fail-safe, in case an ENTITY scope is inadvertently granted to a non-external user
                scopeRestriction =  { entity_id: assertions.authorization.entity_id ?? uuidv4() };
                break;

            case "OWNER":
                //This is the default
                break;

            case "MEMBER":
                scopeRestriction = { member_id: assertions.authentication.member_id };
                break;

            case "SITE":
                scopeRestriction = {
                    site_id: assertions.authentication.site_id,
                    site_access_id: assertions.authentication.user_id,
                    site_authorized: (site_id: string): boolean => {
                        if(assertions.authorization.site_access) {
                            for(let authorized_site_id of assertions.authorization.site_access) {
                                if(authorized_site_id === site_id) return true;
                            }
                        }
                        return false;
                    }
                };
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
                    try{this.emit('trace', 'SERVICE TEST', 'Microservice | TopicHandler (' + topic + ') | ' + request);}catch(err){}

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
                    try{this.emit('trace', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + JSON.stringify(errors ? errors : result));}catch(err){}
                } else {
                    try{this.emit('trace', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | No Response Requested');}catch(err){}
                }
            };

            super.registerTopicHandler(testTopic, topicHandler, instanceID);

        } catch(err) {
            try{this.emit('error', 'SERVICE TEST', 'Microservice | registerTestHandler (' + testTopic + ') Error: ' + err);}catch(err){}
        }
    }

}