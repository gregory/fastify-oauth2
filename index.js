'use strict'

const defaultState = require('crypto').randomBytes(10).toString('hex')

const fp = require('fastify-plugin')
const oauth2Module = require('simple-oauth2')

const promisify = require('util').promisify || require('es6-promisify').promisify

function defaultGenerateStateFunction () {
  return defaultState
}

const oauthPlugin = fp(function (fastify, options, next) {
  if (options.getOptions && typeof options.getOptions !== 'function') {
    return next(new Error('options.getCredentials should be a function'))
  }
  if (typeof options.name !== 'string') {
    return next(new Error('options.name should be a string'))
  }
  if (!options.getOptions) {
    if (typeof options.credentials !== 'object') {
      return next(new Error('options.credentials should be an object'))
    }
    if (typeof options.callbackUri !== 'string') {
      return next(new Error('options.callbackUri should be a string'))
    }
  }
  if (options.generateStateFunction && typeof options.generateStateFunction !== 'function') {
    return next(new Error('options.generateStateFunction should be a function'))
  }
  if (options.checkStateFunction && typeof options.checkStateFunction !== 'function') {
    return next(new Error('options.checkStateFunction should be a function'))
  }
  if (options.startRedirectPath && typeof options.startRedirectPath !== 'string') {
    return next(new Error('options.startRedirectPath should be a string'))
  }
  if (!options.generateStateFunction ^ !options.checkStateFunction) {
    return next(new Error('options.checkStateFunction and options.generateStateFunction have to be given'))
  }

  const name = options.name
  const generateStateFunction = options.generateStateFunction || defaultGenerateStateFunction
  const startRedirectPath = options.startRedirectPath
  const getOptions = options.getOptions || function () {
    return {
      scope: options.scope,
      callbackUri: options.callbackUri,
      credentials: options.credentials
    }
  }

  function defaultCheckStateFunction (state, callback) {
    if (state === defaultState) {
      const opts = getOptions(state)
      callback(null, opts)
      return
    }
    callback(new Error('Invalid state'))
  }
  const checkStateFunction = options.checkStateFunction || defaultCheckStateFunction

  function startRedirectHandler (request, reply) {
    const state = generateStateFunction(request)
    const opts = getOptions(state)
    const oauth2 = oauth2Module.create(opts.credentials)

    const authorizationUri = oauth2.authorizationCode.authorizeURL({
      redirect_uri: opts.callbackUri,
      scope: opts.scope,
      state: state
    })
    reply.redirect(authorizationUri)
  }

  function getAccessTokenFromAuthorizationCodeFlowCallbacked (request, callback) {
    const code = request.query.code
    const state = request.query.state

    checkStateFunction(state, function (err, opts) {
      if (err) {
        callback(err)
        return
      }
      const oauth2 = oauth2Module.create(opts.credentials)
      return oauth2.authorizationCode.getToken({
        code: code,
        redirect_uri: opts.callbackUri
      }, function (error, result) {
        if (error) {
          callback(error)
          return
        }
        if (options.getOptions) {
          callback(null, { result, oauth2, options: opts })
        } else {
          return callback(null, result)
        }
      })
    })
  }
  const getAccessTokenFromAuthorizationCodeFlowPromiseified = promisify(getAccessTokenFromAuthorizationCodeFlowCallbacked)

  function getAccessTokenFromAuthorizationCodeFlow (request, callback) {
    if (!callback) {
      return getAccessTokenFromAuthorizationCodeFlowPromiseified(request)
    }
    getAccessTokenFromAuthorizationCodeFlowCallbacked(request, callback)
  }

  if (startRedirectPath) {
    fastify.get(startRedirectPath, startRedirectHandler)
    if (!fastify.hasDecorator('getAccessTokenFromAuthorizationCodeFlow')) {
      fastify.decorate('getAccessTokenFromAuthorizationCodeFlow', getAccessTokenFromAuthorizationCodeFlow)
    }
  }

  const decoration = {
    getAccessTokenFromAuthorizationCodeFlow
  }
  if (!options.getOptions) {
    const opts = getOptions()
    const oauth2 = oauth2Module.create(opts.credentials)
    Object.assign(decoration, oauth2)
  }

  try {
    fastify.decorate(name, decoration)
  } catch (e) {
    next(e)
    return
  }

  next()
})

oauthPlugin.FACEBOOK_CONFIGURATION = {
  authorizeHost: 'https://facebook.com',
  authorizePath: '/v3.0/dialog/oauth',
  tokenHost: 'https://graph.facebook.com',
  tokenPath: '/v3.0/oauth/access_token'
}

oauthPlugin.GITHUB_CONFIGURATION = {
  tokenHost: 'https://github.com',
  tokenPath: '/login/oauth/access_token',
  authorizePath: '/login/oauth/authorize'
}

oauthPlugin.LINKEDIN_CONFIGURATION = {
  authorizeHost: 'https://www.linkedin.com',
  authorizePath: '/oauth/v2/authorization',
  tokenHost: 'https://www.linkedin.com',
  tokenPath: '/oauth/v2/accessToken'
}

oauthPlugin.GOOGLE_CONFIGURATION = {
  authorizeHost: 'https://accounts.google.com',
  authorizePath: '/o/oauth2/v2/auth',
  tokenHost: 'https://www.googleapis.com',
  tokenPath: '/oauth2/v4/token'
}

module.exports = oauthPlugin
