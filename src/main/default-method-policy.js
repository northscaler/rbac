'use strict'

// NOTE:
// classes: regex identifying securable class names
// roles: regex identifying role class names
// methods: regex identifying method names
// strategy:
//   if strategy === true, GRANT
//   else if strategy === false, DENY
//   else if typeof strategy === 'function', return strategy(clazz, role, action, data): true|false
//   else typeof strategy === 'string', return require(strategy)(clazz, role, action, data): true|false

const policy = [
  {
    roles: /^.*$/,
    classes: /^.*$/,
    methods: /^.*$/,
    strategy: true
  }
]

module.exports = Object.freeze(policy)
