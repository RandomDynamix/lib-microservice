import { NATSClient } from '@randomrod/lib-nats-client';
import base64url from 'base64url';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
const DOMAIN_INTERNAL = 'INTERNAL';
const INTERNAL_PREFIX = 'INTERNAL';
const MESH_PREFIX = 'MESH';
const SUPERADMIN = 'SUPERADMIN';
const QUERY_TIMEOUT = 7500;
export class Microservice extends NATSClient {
    constructor(serviceName) {
        super(serviceName);
        this.sourceVersion = process.env.SOURCE_VERSION || 'LOCAL';
        this.jwtValidator = {
            publicPEM: process.env.JWT_MESH_PUBLIC_PEM ? Buffer.from(process.env.JWT_MESH_PUBLIC_PEM, 'base64').toString('ascii') : null,
            jwtAlgorithm: (process.env.JWT_ALGORITHM || 'RS256'),
        };
        this.serviceMessages = [];
    }
    async init() {
        await super.init();
        if (!this.jwtValidator.publicPEM)
            try {
                this.emit('info', 'no correlation', 'Message Validation NOT Configured');
            }
            catch (err) { }
        this.registerTestHandler();
    }
    async query(topic, context, payload, queryTimeout = QUERY_TIMEOUT, topicPrefix = INTERNAL_PREFIX) {
        if (typeof context !== 'object' || typeof payload !== 'object')
            throw 'INVALID REQUEST: One or more of context or payload are not properly structured objects.';
        let newContext = {
            correlationUUID: context.correlationUUID || uuidv4(),
            siteID: context.siteID || null,
            idToken: context.idToken || null,
            apiKey: context.apiKey || null,
            ephemeralToken: context.ephemeralToken || null,
            proxyToken: context.proxyToken || null,
        };
        let queryData = JSON.stringify({ context: newContext, payload });
        try {
            this.emit('debug', newContext.correlationUUID, `NATS REQUEST (${topic}): ${queryData}`);
        }
        catch (err) { }
        let topicStart = Date.now();
        let queryResponse = await super.queryTopic(`${topicPrefix}.${topic}`, queryData, queryTimeout);
        if (!queryResponse)
            throw `INVALID RESPONSE (${topic}) from NATS Mesh`;
        let topicDuration = Date.now() - topicStart;
        try {
            this.emit('info', newContext.correlationUUID, `NATS RESPONSE (${topic}) | ${topicDuration} ms`);
        }
        catch (err) { }
        try {
            this.emit('debug', newContext.correlationUUID, `NATS RESPONSE (${topic}) | ${topicDuration} ms : ${queryResponse}`);
        }
        catch (err) { }
        let parsedResponse = JSON.parse(queryResponse);
        if (parsedResponse.response.errors)
            throw parsedResponse.response.errors;
        return parsedResponse.response.result;
    }
    publish(topic, context, payload, topicPrefix = INTERNAL_PREFIX) {
        if (typeof context !== 'object' || typeof payload !== 'object')
            throw 'INVALID REQUEST: One or more of context or payload are not properly structured objects.';
        let eventData = JSON.stringify({ context, payload });
        try {
            this.emit('debug', 'no correlation', `NATS PUBLISH (${topic}): ${eventData}`);
        }
        catch (err) { }
        return super.publishTopic(`${topicPrefix}.${topic}`, eventData);
    }
    registerHandler(handlerTopic, fnHandler, minScopeRequired = SUPERADMIN, queue = null, topicPrefix = MESH_PREFIX) {
        try {
            this.serviceMessages.push(handlerTopic);
            let topicHandler = async (request, replyTo, topic) => {
                let errors = null;
                let result = null;
                let topicStart = Date.now();
                topic = topic.substring(topic.indexOf(".") + 1);
                try {
                    try {
                        this.emit('debug', 'SERVICE', 'Microservice | TopicHandler (' + topic + ') | ' + request);
                    }
                    catch (err) { }
                    let parsedRequest = request ? JSON.parse(request) : null;
                    if (!parsedRequest?.context || !parsedRequest?.payload)
                        throw 'INVALID REQUEST: Either context or payload, or both, are missing.';
                    parsedRequest.context.assertions = await this.validateRequestAssertions(topic, parsedRequest.context, minScopeRequired);
                    parsedRequest.context.topic = topic;
                    result = await fnHandler(parsedRequest);
                    if (typeof result !== 'object') {
                        result = {
                            status: result
                        };
                    }
                    else if (result === {}) {
                        result = {
                            status: "SUCCESS"
                        };
                    }
                }
                catch (err) {
                    let error = `Service Error(${fnHandler.name.substring(6)}): ${JSON.stringify(err)}`;
                    try {
                        this.emit('error', 'SERVICE', error);
                    }
                    catch (err) { }
                    if (!errors)
                        errors = [err];
                }
                let topicDuration = Date.now() - topicStart;
                if (replyTo) {
                    this.publishResponse(replyTo, errors, result);
                    try {
                        this.emit('info', 'SERVICE', `Microservice | topicHandler (${topic}) | ${topicDuration} ms`);
                    }
                    catch (err) { }
                    try {
                        this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + topicDuration.toString() + 'ms | ' + JSON.stringify(errors ? errors : result));
                    }
                    catch (err) { }
                }
                else {
                    try {
                        this.emit('info', 'SERVICE', `Microservice | topicHandler (${topic}) | ${topicDuration} ms`);
                    }
                    catch (err) { }
                    try {
                        this.emit('debug', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + topicDuration.toString() + 'ms | No Response Requested');
                    }
                    catch (err) { }
                }
            };
            super.registerTopicHandler(`${topicPrefix}.${handlerTopic}`, topicHandler, queue);
        }
        catch (err) {
            try {
                this.emit('error', 'SERVICE', 'Microservice | registerTopicHandler (' + handlerTopic + ') Error: ' + err);
            }
            catch (err) { }
        }
    }
    verifyToken(token, publicPEM, algorithm) {
        try {
            let verificationPEM = publicPEM || this.jwtValidator.publicPEM || null;
            let verificationAlgo = algorithm || this.jwtValidator.jwtAlgorithm || null;
            if (!verificationPEM || !verificationAlgo)
                throw "JWTValidator Not Configured";
            return jwt.verify(token, verificationPEM, { algorithms: [verificationAlgo] });
        }
        catch (err) {
            try {
                this.emit('error', 'MICROSERVICE', `Error Verifying Token: ${JSON.stringify(err)}`);
            }
            catch (err) { }
        }
        return null;
    }
    decodeToken(token) {
        try {
            let decoded = jwt.decode(token, { complete: true });
            if (decoded?.payload)
                return decoded.payload;
        }
        catch (err) {
            try {
                this.emit('error', 'MICROSERVICE', `Error Decoding Token: ${JSON.stringify(err)}`);
            }
            catch (err) { }
        }
        return null;
    }
    verifyParameters(test, fields) {
        if (!test)
            throw 'VALIDATION: Missing Verification Test Object';
        for (let field of fields) {
            let fieldEntries = field.split(",");
            if (fieldEntries.length > 1) {
                let anyFound = false;
                for (let fieldEntry of fieldEntries) {
                    if (test.hasOwnProperty(fieldEntry) && test[field] !== null)
                        anyFound = true;
                }
                if (!anyFound)
                    throw `VALIDATION: Missing At Least One Parameter Of - ${field}`;
            }
            else {
                if (!test.hasOwnProperty(field) || test[field] === null)
                    throw `VALIDATION: Missing Parameter - ${field}`;
            }
        }
    }
    async validateRequestAssertions(topic, context, minScopeRequired) {
        if (!context.ephemeralToken && minScopeRequired !== 'NOAUTH')
            throw 'UNAUTHORIZED: Ephemeral Authorization Token Missing';
        if (!context.ephemeralToken)
            return null;
        let token_assertions = null;
        try {
            let ephemeral_assertions = null;
            if (this.jwtValidator.publicPEM && this.jwtValidator.jwtAlgorithm) {
                ephemeral_assertions = await this.verifyToken(context.ephemeralToken);
                if (ephemeral_assertions)
                    ephemeral_assertions.signatureVerified = true;
            }
            else {
                ephemeral_assertions = this.decodeToken(context.ephemeralToken);
                if (ephemeral_assertions)
                    ephemeral_assertions.signatureVerified = false;
            }
            if (!ephemeral_assertions)
                throw "Error Decoding Ephemeral Authorization Token";
            if (!ephemeral_assertions.exp)
                throw "Invalid Ephemeral Authorization Token: Missing exp";
            if (ephemeral_assertions.exp < Date.now())
                throw "Ephemeral Authorization Token Expired";
            let requestDomain = ephemeral_assertions.domain || DOMAIN_INTERNAL;
            if (!ephemeral_assertions.ephemeralAuth)
                throw "Invalid Ephemeral Authorization Token: Missing ephemeralAuth";
            let ephemeralAuth = JSON.parse(base64url.decode(ephemeral_assertions.ephemeralAuth));
            if (!ephemeralAuth.authentication || !ephemeralAuth.authorization)
                throw "Invalid Ephemeral Authorization Token Payload";
            let requestAuthentication = ephemeralAuth.authentication;
            let requestAuthorization = ephemeralAuth.authorization;
            let signatureVerified = ephemeral_assertions.signatureVerified;
            if (context.proxyToken) {
                let proxy_assertions = null;
                if (this.jwtValidator.publicPEM && this.jwtValidator.jwtAlgorithm) {
                    proxy_assertions = await this.verifyToken(context.proxyToken);
                }
                else {
                    proxy_assertions = this.decodeToken(context.proxyToken);
                }
                if (!proxy_assertions)
                    throw "Error Decoding Proxy Authorization Token";
                if (!proxy_assertions.exp)
                    throw "Invalid Proxy Authorization Token: Missing exp";
                if (proxy_assertions.exp < Date.now())
                    throw "Proxy Authorization Token Expired";
                if (!proxy_assertions.ephemeralAuth)
                    throw "Invalid Proxy Authorization Token: Missing ephemeralAuth";
                let proxyAuth = JSON.parse(base64url.decode(proxy_assertions.ephemeralAuth));
                if (!proxyAuth.authentication || !proxyAuth.authorization)
                    throw "Invalid Proxy Authorization Token Payload";
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
            token_assertions.authorization.scope = (topic) => {
                if (token_assertions.authorization.superAdmin)
                    return '*';
                return token_assertions.authorization.permissions[topic] || 'NONE';
            };
            let assertedScope = token_assertions.authorization.scope(topic);
            token_assertions.authorization.scopeRestriction = this.authorizeScope(assertedScope, token_assertions, minScopeRequired);
            token_assertions.authorization.siteScopeAuthorized = (site_id) => {
                let scopeRestriction = token_assertions.authorization.scopeRestriction;
                if (!scopeRestriction)
                    return true;
                if (scopeRestriction.site_access) {
                    for (let site_access_site_id of scopeRestriction.site_access) {
                        if (site_access_site_id === site_id)
                            return true;
                    }
                }
                return false;
            };
        }
        catch (err) {
            throw `UNAUTHORIZED: validateRequestAssertions Error: ${JSON.stringify(err)}`;
        }
        return token_assertions;
    }
    proxyAuthorization(baseAuthorization, proxyAuthorization) {
        if (baseAuthorization.superAdmin)
            return baseAuthorization;
        if (proxyAuthorization.superAdmin) {
            baseAuthorization.superAdmin = true;
            baseAuthorization.roleLevel = proxyAuthorization.roleLevel;
            return baseAuthorization;
        }
        for (let permission in proxyAuthorization.permissions) {
            let basePermission = baseAuthorization.permissions[permission];
            let proxyPermission = proxyAuthorization.permissions[permission];
            if (!basePermission)
                baseAuthorization.permissions[permission] = proxyPermission;
            else {
                switch (basePermission) {
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
                        if (proxyPermission === "*" || proxyPermission === "SITE") {
                            baseAuthorization.permissions[permission] = proxyPermission;
                        }
                        break;
                    case "SITE":
                        if (proxyPermission === "*") {
                            baseAuthorization.permissions[permission] = proxyPermission;
                        }
                        break;
                    case "*":
                        break;
                }
            }
        }
        if (proxyAuthorization.roleLevel > baseAuthorization.roleLevel)
            baseAuthorization.roleLevel = proxyAuthorization.roleLevel;
        return baseAuthorization;
    }
    authorizeScope(assertedScope, assertions, minScopeRequired) {
        if (assertions.authorization.superAdmin)
            return null;
        switch (minScopeRequired) {
            case 'SUPERADMIN':
                if (!assertions.authorization.superAdmin)
                    throw 'UNAUTHORIZED: Requires SUPERADMIN Permissions';
                break;
            case '*':
                if (assertedScope !== '*')
                    throw 'UNAUTHORIZED:  Requires GLOBAL Permission Scope';
                break;
            case 'SITE':
                if (assertedScope !== '*' &&
                    assertedScope !== 'SITE')
                    throw 'UNAUTHORIZED:  Requires SITE Permission Scope or Greater';
                break;
            case 'MEMBER':
                if (assertedScope !== '*' &&
                    assertedScope !== 'SITE' &&
                    assertedScope !== 'MEMBER')
                    throw 'UNAUTHORIZED:  Requires MEMBER Permission Scope or Greater';
                break;
            case 'OWNER':
                if (assertedScope !== '*' &&
                    assertedScope !== 'SITE' &&
                    assertedScope !== 'MEMBER' &&
                    assertedScope !== 'OWNER')
                    throw 'UNAUTHORIZED:  Requires OWNER Permission Scope or Greater';
                break;
            case 'ENTITY':
                if (assertedScope !== '*' &&
                    assertedScope !== 'SITE' &&
                    assertedScope !== 'MEMBER' &&
                    assertedScope !== 'OWNER' &&
                    assertedScope !== 'ENTITY')
                    throw 'UNAUTHORIZED:  Requires ENTITY Permission Scope or Greater';
                break;
            case 'NOAUTH':
                return null;
                break;
            default:
                throw `SERVER ERROR:  Invalid Scope Requirement (${minScopeRequired})`;
        }
        let scopeRestriction = { user_id: assertions.authentication.user_id };
        switch (assertedScope) {
            case "ENTITY":
                scopeRestriction = { entity_id: assertions.authorization.entity_id ?? uuidv4() };
                break;
            case "OWNER":
                break;
            case "MEMBER":
                scopeRestriction = { member_id: assertions.authentication.member_id };
                break;
            case "SITE":
                scopeRestriction = {
                    site_id: assertions.authentication.site_id,
                    site_access_id: assertions.authentication.user_id,
                    site_authorized: (site_id) => {
                        if (assertions.authorization.site_access) {
                            for (let authorized_site_id of assertions.authorization.site_access) {
                                if (authorized_site_id === site_id)
                                    return true;
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
    publishResponse(replyTopic, errors, result) {
        let response = JSON.stringify({
            response: {
                errors: errors,
                result: result
            }
        });
        return super.publishTopic(replyTopic, response);
    }
    versionNode() {
        return { version: this.sourceVersion, messages: this.serviceMessages };
    }
    registerTestHandler() {
        let instanceID = uuidv4();
        let testTopic = `TEST.${this.serviceName}.${instanceID}`;
        try {
            let topicHandler = async (request, replyTo, topic) => {
                let errors = null;
                let result = null;
                try {
                    try {
                        this.emit('trace', 'SERVICE TEST', 'Microservice | TopicHandler (' + topic + ') | ' + request);
                    }
                    catch (err) { }
                    let parsedRequest = request ? JSON.parse(request) : null;
                    if (!parsedRequest)
                        throw 'INVALID REQUEST: Either context or payload, or both, are missing.';
                    result = this.versionNode();
                }
                catch (err) {
                    let error = `Test Error(${topic}): ${JSON.stringify(err)}`;
                    try {
                        this.emit('error', 'SERVICE TEST', error);
                    }
                    catch (err) { }
                    if (!errors)
                        errors = [err];
                }
                if (replyTo) {
                    this.publishResponse(replyTo, errors, result);
                    try {
                        this.emit('trace', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | ' + JSON.stringify(errors ? errors : result));
                    }
                    catch (err) { }
                }
                else {
                    try {
                        this.emit('trace', 'SERVICE', 'Microservice | topicHandler (' + topic + ') Response | No Response Requested');
                    }
                    catch (err) { }
                }
            };
            super.registerTopicHandler(testTopic, topicHandler, instanceID);
        }
        catch (err) {
            try {
                this.emit('error', 'SERVICE TEST', 'Microservice | registerTestHandler (' + testTopic + ') Error: ' + err);
            }
            catch (err) { }
        }
    }
}
