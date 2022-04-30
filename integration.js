'use strict';

const schedule = require('node-schedule');
const requestCb = require('postman-request');
const config = require('./config/config');
const { promisify } = require('util');

const EVERY_MIDNIGHT = '0 0 * * *';
let requestDefault;
let Logger;
let cveLookupMap;


function startup(logger) {
  return async function (cb) {
    Logger = logger;

    let defaults = {};

    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
      defaults.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
      defaults.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
      defaults.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
      defaults.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
      defaults.proxy = config.request.proxy;
    }

    if (typeof config.request.rejectUnauthorized === 'boolean') {
      defaults.rejectUnauthorized = config.request.rejectUnauthorized;
    }

    let requestCbDefault = requestCb.defaults(defaults);

    requestDefault = promisify(requestCbDefault);
    try {
      await loadVulnList();
      schedule.scheduleJob(EVERY_MIDNIGHT, loadVulnList);
    } catch (err) {
      return cb(errorToPojo(err));
    }
    cb();
  };
}

function errorToPojo(err) {
  if (err instanceof Error) {
    return {
      // Pull all enumerable properties, supporting properties on custom Errors
      ...err,
      // Explicitly pull Error's non-enumerable properties
      name: err.name,
      message: err.message,
      stack: err.stack,
      detail: err.detail ? err.detail : 'Google compute engine had an error'
    };
  }
  return err;
}

function RequestException(message, meta) {
  this.message = message;
  this.meta = meta;
}

async function loadVulnList() {
  Logger.info('Loading Vulnerability List');
  const requestOptions = {
    uri: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    json: true
  };

  const response = await requestDefault(requestOptions);
  if (response.statusCode === 200 && Array.isArray(response.body.vulnerabilities)) {
    cveLookupMap = new Map();
    response.body.vulnerabilities.forEach((cve) => {
      cveLookupMap.set(cve.cveID.toLowerCase(), cve);
    });
    Logger.info(`Finished loading ${cveLookupMap.size} CVEs`);
  } else {
    Logger.error({ response }, 'Unexpected HTTP Status Code');
    throw new RequestException(`Unexpected status code ${response.statusCode} received`, response);
  }
}

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function doLookup(entities, options, cb) {
  let lookupResults = [];

  entities.forEach((entity) => {
    let searchResult = cveLookupMap.get(entity.value.toLowerCase());
    Logger.info({ searchResult }, 'Search Result');
    if (searchResult) {
      lookupResults.push({
        entity,
        data: {
          summary: [{
            type: 'danger',
            text: searchResult.vendorProject
          }],
          details: searchResult
        }
      });
    } else {
      lookupResults.push({
        entity,
        data: null
      });
    }
  });

  cb(null, lookupResults);
}

module.exports = {
  doLookup,
  startup
};
