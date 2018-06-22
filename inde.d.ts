declare module "express-sslify" {
  import { RequestHandler } from "express";

  interface Options {
    /** Set to true if the x-forwarded-proto HTTP header should be trusted (e.g. for typical reverse proxy configurations) */
    trustProtoHeader?: boolean;
    /** Set to true if Azure's x-arr-ssl HTTP header should be trusted (only use in Azure environments) */
    trustAzureHeader?: boolean;
    /** Set to true if the x-forwarded-host HTTP header should be trusted */
    trustXForwardedHostHeader?: boolean;
  }

  /**
   * enforceHTTPS
   *
   * @param {Options} [options]
   * @param {Boolean} [options[trustProtoHeader]=false] - Set to true if the x-forwarded-proto HTTP header should be trusted (e.g. for typical reverse proxy configurations)
   * @param {Boolean} [options[trustAzureHeader]=false] - Set to true if Azure's x-arr-ssl HTTP header should be trusted (only use in Azure environments)
   * @param {Boolean} [options[trustXForwardedHostHeader]=false] - Set to true if the x-forwarded-host HTTP header should be trusted
   * @api public
   */
  function HTTPS(options?: Options): RequestHandler;

  export { HTTPS };
}
