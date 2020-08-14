'use strict'

const DEFAULT_POLICY = require('./default-method-policy')
const AbstractRoleBasedAccessControlRepository = require('./AbstractRoleBasedAccessControlRepository')

/**
 * Role-based access control repository whose securables are methods on classes, hence, the only action supported is, of course, "invoke".
 * This subclass's securables take the form `{ securable: { class: '...', method: '...' }}`.
 * Its policy entries include the standard `roles` regular expression and `strategy` values (`true`, `false`, or access control strategy functions), and also `classes` & `methods` that each are regular expressions describing the names of methods on classes that are invocable.
 *
 * For example, to permit `Administrator`s to invoke any method on any class, the policy would be
 * ```javascript
 * const policy = [{
 *   roles: /^Administrator$/, // role name regex
 *   strategy: true,           // true means "permit", false means "explicitly deny"
 *   classes: /^.+$/           // regex of class names
 *   methods: /^.+$/           // regex of method names
 * }]
 * ```
 * Then, let's say you want to enhance the policy to allow `Teller`s & `Manager`s to open & close accounts, but `Teller`s can only close _low-value_ accounts:
 * ```javascript
 * policy.push({
 *   // Tellers & Managers can call Account.open method
 *   roles: /^Teller|Manager$/,
 *   classes: /^Account$/,
 *   methods: /^open$/,
 *   strategy: true
 * }, {
 *   // Only Managers can close high-value accounts
 *   classes: /^Account$/,
 *   methods: /^close$/,
 *   strategy: ({role, data}) => { // custom access control strategy function
 *     switch (role) {
 *       case 'Teller': return data?.account?.balance < 10000
 *       case 'Manager': return true
 *       default: return false
 *     }
 *   }
 * })
 * ```
 *
 * Now, hydrate a `MethodAccessControlRepository` with your policy:
 * ```javascript
 * const rbac = new MethodAccessControlRepository(policy)
 * putRbacSomewhere(rbac) // wherever you do
 * ```
 *
 * Lastly, make the repository available in whatever context you want to (`request` variable in a webapp, [`AsyncLocalStorage`](https://nodejs.org/api/async_hooks.html#async_hooks_class_asynclocalstorage) in a Node.js app or library, decorator function, etc) and interrogate it:
 * ```javascript
 * const rbac = getRbacFromSomewhere()                   // wherever you do
 * const roles = getCallerRoles()                        // however you do
 * const securable = {class: 'Account', method: 'close'} // you know this at design time
 *
 * if (!rbac.permits({role: roles, securable}) {         // (role can be singular or an array)
 *   throw new Error(`no roles among ${roles.join(',')} permitted to invoke ${securable.class}.${securable.method}`)
 * }
 * ```
 */
class MethodAccessControlRepository extends AbstractRoleBasedAccessControlRepository {
  constructor (policy) {
    super(policy || DEFAULT_POLICY)
  }

  _filterSecurable ({ entry, securable }) {
    return entry?.classes.test(securable?.class) && entry?.methods.test(securable?.method)
  }
}

module.exports = MethodAccessControlRepository
