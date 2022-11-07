'use strict';

const schedule = require('node-schedule');
const requestCb = require('postman-request');
const config = require('./config/config');
const fs = require('fs');
const { promisify } = require('util');

const EVERY_MIDNIGHT = '0 0 * * *';
let requestDefault;
let Logger;
let cveLookupMap;
let reloadRunning = false;
let reloadScheduled = false;

function startup(logger) {
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
      detail: err.detail ? err.detail : 'CISA Known Exploited Vulnerabilities integration had an error'
    };
  }
  return err;
}

function RequestException(message, meta) {
  this.message = message;
  this.meta = meta;
}

async function loadVulnList() {
  reloadRunning = true;
  try {
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
  } finally {
    reloadRunning = false;
  }
}

function _getSummaryTags(searchResult) {
  const tags = [];
  let vendor = searchResult.vendorProject;
  let product = searchResult.product;

  if (product.toLowerCase().startsWith(vendor.toLowerCase())) {
    tags.push(product);
  } else {
    tags.push(`${vendor} ${product}`);
  }

  return tags;
}

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
async function doLookup(entities, options, cb) {
  let lookupResults = [];

  if (reloadScheduled === false) {
    try {
      await loadVulnList();
      schedule.scheduleJob(EVERY_MIDNIGHT, loadVulnList);
      reloadScheduled = true;
    } catch (err) {
      return cb(errorToPojo(err));
    }
  }

  entities.forEach((entity) => {
    if (reloadRunning) {
      lookupResults.push({
        entity,
        data: {
          summary: ['Temporarily unavailable. Retry search'],
          details: {
            reloadRunning: true
          }
        }
      });
      return;
    }

    let searchResult = cveLookupMap.get(entity.value.toLowerCase());
    Logger.trace({ searchResult }, 'Search Result');
    if (searchResult) {
      lookupResults.push({
        entity,
        data: {
          summary: _getSummaryTags(searchResult),
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
