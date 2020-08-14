# rbac
A role-based access control supporting library

This library provides a means to declare policies governing access control to arbitrary securables based on roles and interrogate those policies to make access control decisions.

> NOTE: In the context of this discussion & this module, the term "role" refers to a _type_, not an instance.

## Security concepts
In any security decision, there are four fundamental things required:
* `Securable`: the thing access to which is being governed.
* `Principal`: the thing that is attempting to perform an `Action` on a `Securable`.
This is sometimes also known as a "subject".
* `Action`: the activity that is being attempted.
* `Access Control Entry`: the thing that binds `Securable`, `Principal`s and `Action`s together along with an access control strategy that determines whether the activity is allowed to take place.
`Access Control Entry`s are also sometimes known as "permissions", but that implies a positive sense that breaks down when the security implementation supports explicit denials.
`Acess Control Entry`s are often collected into access control lists (or ACLs).
Common access control strategies are "permit" & "deny", but can also be algorithmic depending on context, like "permit only if it's sunny".

### Mapping of security concepts to this library
In the context of this library, a `Principal` is represented by a named role as a string.

The base class in this library, `AbstractRoleBasedAccessControlRepository`, supports arbitrary `Securable`s, but also provides a concrete implementation, `MethodAccessControlRepository`, that secures methods on JavaScript classes; the `Securable`s for that implementation are, then, the methods themselves.

The notion of `Action` has not yet been made explicit in this library.
In the case of `MethodAccessControlRepository`, the `Action` is to simply invoke the method.
The library authors anticipate adding support for `Action`s in a future release.

The notion of an access control list is manifested as a security policy that you declare and pass to a repository's constructor.
Each policy is a JavaScript `Array` of entries of literal `Object`s.
Each entry in the policy is an `Access Control Entry`.
Each entry can have a `roles` property and/or a `strategy` property, but it _must_ have some representation of the `Securable` whose access control is being declared.
Since roles in this implementation are `String`s, the type of an entry's `roles` is a `RegExp` that is matched to role strings.
An entry's `strategy` can be
* the JavaScript literal `true`, to indicate that access is permitted,
* the JavaScript literal `false`, to indicate that access is explicitly denied, or
* a `Function` that takes contextual information and returns a `Boolean` indicating whether or not access is permitted.
 
In the absence of the `roles` property, the value is assumed to be all roles, or the regular expression `/^.+$/`.

In the absence of the `strategy` property, this library makes the conservative choice to deny, meaning the default strategy is `false`.

Each concrete implementation of a repository determines what property or properties comprise the identification of the `Securable`.
In the case of `MethodAccessControlRepository`, the `Securable` is a JavaScript `class` method, so the repository expects two properties, `classes` & `methods`, both of which are expected to be `RegExp`s and are matched against the values given in the repository's interrogation methods.

## Capabilities
Each repository, once given a policy, allows the consumer to interrogate whether a role is allowed to access a `Securable`.
The interrogative methods are as follows.
* `permits({role, securable, data})`: returns `true` if the given `role` (which can also be an array of roles) is (are) allowed to access the `securable` given optional, arbitrary, contextual `data`, else returns `false`.
* `explicitlyDenies({role, securable, data})`: returns `true` if the given `role` (or roles) is (are) explicitly denied the ability to access the `securable` given optional, arbitrary, contextual `data`, else returns `false`. 

Note the subtle distinction between the two.
Users of this library will almost always use `permits`; `expicitlyDenies` is intended for more subtle use cases. 

## Example
Let's take `MethodAccessControlRepository` as an example.

First, declare your policy.
We want `Administrator`s to be able to do anything, `Teller`s & `Manager`s to be able to open `Account`s, but only `Manager`s can close high-value `Account`s.
```javascript
// in file security.js

module.exports = [{
  // Administrators can do anything
  roles: /^Administrator$/, // role name regex
  strategy: true,           // true means "permit", false means "explicitly deny"
  classes: /^.+$/,          // regex of class names
  methods: /^.+$/           // regex of method names
}, {
  // Tellers & Managers can open accounts
  roles: /^Teller|Manager$/,
  strategy: true,
  classes: /^Account$/,
  methods: /^open$/
}, {
  // Only Managers can close high-value accounts
  strategy: ({role, account}) => { // custom access control strategy function
    switch (role) {
      case 'Teller': return account.balance < 10000
      case 'Manager': return true
      default: return false
    }
  },
  classes: /^Account$/,
  methods: /^close$/
}]
```

Next, instantiate your repository with the policy.
```javascript
// in file rbac.js

const { MethodAccessControlRepository } = require('@northscaler/rbac')
const acl = require('./security')

module.exports = new MethodAccessControlRepository(policy)
```
Now, you have a repository that you can query for access control decisions.
To make use of it, you need to either manually code calls to it along your regular call paths, or use a slicker, aspect-oriented solution like [JavaScript decorators]() to intercept method calls and make access control decisions.

Here's a simple example using manual, inline security calls.
```javascript
// in file Account.js
const getCallerRoles = require('./getCallerRoles') // magic that gets the roles of the current caller
const rbac = require('./rbac') // from above

function checkSecurity({ clazz, method, data}) {
 if (!rbac.permits({role: getCallerRoles(), securable: {class: clazz, method}, data})) {
   throw new Error(`no roles among ${roles.join(',')} permitted to invoke ${clazz}.${method}`)
 }
}

class Account {
  static open({id, firstName, lastName}) {
    checkSecurity({clazz: 'Account', method: 'open'})
    return new Account({id, firstName, lastname})  
  }

  constructor({id, firstName, lastName}) {
    this.id = id
    this.firstName = firstName
    this.lastName = lastName
    this.balance = 0  
  }

  close() {
    checkSecurity({clazz: 'Account', method: 'close', data: this}) // `this` will show up as `account` in strategy above
    // ...logic to close account
  }
}
```
