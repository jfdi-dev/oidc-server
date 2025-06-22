/* eslint-disable no-console */

import Provider from "oidc-provider";
import errors from "oidc-provider";
import Koa from "koa";
import mount from "koa-mount";
import { readFileSync } from "fs";

const port = process.env.PORT || 3000;

const config = JSON.parse(readFileSync("/config/config.json", "utf-8"));
console.log(config);

// TODO could be refactored to ISSUER_BASEURL with http://localhost directly
// Or we could allow to set koa app proxy = true to autodetect these from the x-forwarded-* headers:
// https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#trusting-tls-offloading-proxies
const proto = process.env.ISSUER_PROTO || "http://";
const host = process.env.ISSUER_HOST || "localhost";
const prefix = process.env.ISSUER_PREFIX || "/";
const domain = process.env.EMAIL_DOMAIN || "@domain.com";

const resourcesList = config.custom?.resourcesList;

if (resourcesList) {
  config.features.resourceIndicators = {
    enabled: true,
    defaultResource: async function (ctx, client, oneOf) {
      // @param ctx - koa request context
      // @param client - client making the request
      // @param oneOf {string[]} - The authorization server needs to select **one** of the values provided.
      //                           Default is that the array is provided so that the request will fail.
      //                           This argument is only provided when called during
      //                           Authorization Code / Refresh Token / Device Code exchanges.
      console.log("resourceIndicators.defaultResource:");
      console.log({ client });
      console.log(ctx.oidc.params);
      return Array.isArray(ctx.oidc.params?.audience)
        ? ctx.oidc.params?.audience[0]
        : ctx.oidc.params?.audience;
    },
    getResourceServerInfo: async function (ctx, resourceIndicator, client) {
      // @param ctx - koa request context
      // @param resourceIndicator - resource indicator value either requested or resolved by the defaultResource helper.
      // @param client - client making the request
      console.log("resourceIndicators.getResourceServerInfo:");
      console.log({ resourceIndicator, client });
      if (!resourceIndicator || !resourcesList[resourceIndicator]) {
        throw new errors.InvalidRequest(
          "invalid_request",
          "Invalid resource server"
        );
      }

      // Get this resource infos
      var targetResourceServer = resourcesList[resourceIndicator];

      // Client request access_token for api must defined these 2 metadata: allowResources, ressourcesScopes
      if (
        !Array.isArray(client.allowedResources) ||
        !client.allowedResources.includes(resourceIndicator)
      ) {
        console.log("xxx client.allowedResources failed validation");
        console.log(client.allowedResources);
        console.log(resourceIndicator);
        throw new errors.InvalidClientMetadata(
          "invalid_client_metadata",
          "allowedResources & allowedResources are mandatory or you cannot request access token for this server"
        );
      }

      // Now ensure client get access_token for scope it not defined
      let clientAllowedScope = "";
      if (client.resourcesScopes) {
        var scopesList = client.resourcesScopes.split(" ");
        clientAllowedScope = scopesList.filter((scopeItem) => {
          return targetResourceServer.scope.includes(scopeItem);
        });
      } else {
        console.log("xxx client.resourcesScopes is not set");
        console.log(client.resourcesScopes);
        throw new errors.InvalidClientMetadata(
          "invalid_client_metadata",
          "Please specify at least one scope"
        );
      }

      console.log(">>----Client ressource allowed:", client.allowedResources);
      console.log(">>----Client ressource scopes:", client.resourcesScopes);
      console.log(">>----Target ressource server is:", targetResourceServer);
      console.log(">>----resourceIndicator is :", resourceIndicator);
      console.log(">>----Client Scope allowed:", clientAllowedScope.join(" "));

      // Update the acces_token ressource to issued
      targetResourceServer.scope = clientAllowedScope.join(" ");
      return targetResourceServer;
    },
    useGrantedResource: async function (ctx, model) {
      // @param ctx - koa request context
      // @param model - depending on the request's grant_type this can be either an AuthorizationCode, BackchannelAuthenticationRequest,
      //                RefreshToken, or DeviceCode model instance.
      console.log("resourceIndicators.useGrantedResource:");
      console.log({ model });
      return true;
    },
  };
}

const oidcConfig = {
  async findAccount(ctx, id) {
    return {
      accountId: id,
      async claims() {
        return { sub: id, name: id, email: id + domain };
      },
    };
  },
  clientBasedCORS() {
    // ctx.oidc.route can be used to exclude endpoints from this behaviour, in that case just return
    // true to always allow CORS on them, false to deny
    // you may also allow some known internal origins if you want to
    return true;
  },
  ...config,
  pkce: {
    // this needs to be a function, so return the constant value from config...
    required: () => config.pkce?.required ?? false,
  },
  extraTokenClaims: async () => config.extraTokenClaims ?? {},
  // clients: clientConfigs.map(clientConfig => ({
  //   client_id: clientConfig.clientId,
  //   redirect_uris: clientConfig.redirect_uris,
  //   response_types: ['id_token token', 'code'],
  //   grant_types: ['implicit', 'authorization_code'],
  //   token_endpoint_auth_method: 'none',
  //   post_logout_redirect_uris: [clientConfig.clientLogoutRedirectUri]
  // }))
};

const issuer = `${proto}${host}:${port}${prefix}`;
const oidc = new Provider(issuer, oidcConfig);
console.log(`OIDC Provider created at "${issuer}"...`);

const { invalidate: orig } = oidc.Client.Schema.prototype;

oidc.Client.Schema.prototype.invalidate = function invalidate(message, code) {
  if (code === "implicit-force-https" || code === "implicit-forbid-localhost") {
    return;
  }

  orig.call(this, message);
};

const app = new Koa();
app.use(mount(prefix, oidc.app));

// TODO can this be always enabled? It is necessary for https but not necessary for http
// because the server generates urls in openid-configuration from ctx.href
if (proto === "https://") {
  app.proxy = true;
}

app.listen(port);
