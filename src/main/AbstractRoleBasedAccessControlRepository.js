'use strict'

const {
  MethodNotImplementedError,
  MissingRequiredArgumentError,
  IllegalArgumentError
} = require('@northscaler/error-support')

/**
 * Abstract base class implementing role-based access control interrogations of some abstract securable based on a given security policy.
 * This class is not intended to be publicly consumed directly, only its concrete subclasses.
 *
 * This class offers interrogations of its policy as to whether a given role is permitted to take and not explicitly denied permission to take particular actions.
 * Security policies are defined externally to this class and then passed in the constructor.
 *
 * The sweet spot for this class is to use subclasses of it along with some aspect-oriented solution, like [JavaScript decorators](https://github.com/tc39/proposal-decorators) or [@northscaler/aspectify](https://www.npmjs.com/package/@northscaler/aspectify) to intercept incoming calls and make access control decisions about them.
 */
class AbstractRoleBasedAccessControlRepository {
  /**
   * Abstract method to filter policy entries pertaining to the given securable.
   * Subclasses _must_ override and provide an implementation.
   *
   * @param entry The policy entry.
   * @param securable
   * @return {boolean} Whether the given entry pertains to the given securable.
   * @private
   */
  _filterSecurable ({ entry, securable }) {
    throw new MethodNotImplementedError({ info: '_filterSecurable' })
  }

  /**
   * Constructs a new instance.
   * This class should not be publicly consumed, only its concrete subclasses.
   *
   * @param {object[]} policy An array of policy entries.
   * @protected
   */
  constructor (policy) {
    if (!policy) throw new MissingRequiredArgumentError({ info: 'policy' })
    if (!Array.isArray(policy)) throw new IllegalArgumentError({ info: 'policy', msg: 'policy must be an array' })

    this._policy = this._scrubPolicy(policy)
  }

  _scrubPolicy (policy) {
    return policy.map(entry => ({
      ...entry,
      roles: entry.roles || /^.+$/,
      strategy: entry.strategy || false
    }))
  }

  permits ({ role, securable, data }) {
    if (Array.isArray(role)) {
      return !role.map(it => this.explicitlyDenies({ role: it, securable, data })).includes(true) &&
        role.map(it => this.permits({ role: it, securable, data })).includes(true)
    }

    const entries = this._findEntries({ role, securable })

    return !this._explicitlyDenies({ entries, role, securable, data }) &&
      this._permits({ entries, role, securable, data })
  }

  explicitlyDenies ({ role, securable, data }) {
    if (Array.isArray(role)) {
      const results = role.map(it => this.explicitlyDenies({ role: it, securable, data }))
      return results.includes(true)
    }

    return this._explicitlyDenies({
      role, securable, data, entries: this._findEntries({ role, securable })
    })
  }

  _permits ({ entries, role, securable, data }) {
    return this._interrogate({ entries, role, securable, data, permit: true })
  }

  _explicitlyDenies ({ entries, role, securable, data }) {
    return this._interrogate({ entries, role, securable, data, permit: false })
  }

  _interrogate ({ entries, role, securable, data, permit }) {
    for (const it of entries) {
      if (typeof it.strategy === 'boolean' && it.strategy === permit) {
        return true
      }
      if (typeof it.strategy === 'function') {
        const permitted = it.strategy({ role, securable, data })
        if (permit && permitted) return true
        if (!permit && !permitted) return false
      }
    }
    return false
  }

  _findEntries ({ role, securable }) {
    return this._policy.filter(entry =>
      this._filterRoles({ entry, role }) && this._filterSecurable({ entry, securable })
    )
  }

  _filterRoles ({ entry, role }) {
    return !entry?.roles || entry?.roles.test(role)
  }
}

module.exports = AbstractRoleBasedAccessControlRepository
