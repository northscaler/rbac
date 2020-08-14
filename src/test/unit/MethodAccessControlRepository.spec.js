/* global describe, it */
'use strict'

const chai = require('chai')
chai.use(require('dirty-chai'))
const expect = chai.expect
const uuid = require('uuid').v4

const { MethodAccessControlRepository, AuthorizationError } = require('../../main')

describe('unit tests of MethodAccessControlRepository', () => {
  it('should permit any role by default', () => {
    const repo = new MethodAccessControlRepository()
    const rcm = { role: uuid(), securable: { class: 'Foo', method: 'bar' } }

    expect(repo.explicitlyDenies(rcm)).to.be.false()
    expect(repo.permits(rcm)).to.be.true()
  })

  it('should permit any role when roles omitted in policy', () => {
    const policy = [{
      classes: /^Foo$/,
      methods: /^bar$/,
      strategy: true
    }]
    const repo = new MethodAccessControlRepository(policy)
    const rcm = { role: uuid(), securable: { class: 'Foo', method: 'bar' } }

    expect(repo.explicitlyDenies(rcm)).to.be.false()
    expect(repo.permits(rcm)).to.be.true()
  })

  it('should deny all roles when strategy omitted in policy', () => {
    const policy = [{
      classes: /^Foo$/,
      methods: /^bar$/
    }]
    const repo = new MethodAccessControlRepository(policy)
    const rcm = { role: uuid(), securable: { class: 'Foo', method: 'bar' } }

    expect(repo.explicitlyDenies(rcm)).to.be.true()
    expect(repo.permits(rcm)).to.be.false()
  })

  it('should permit a known role & not permit unknown role', () => {
    const policy = [{
      roles: /^Manager$/,
      classes: /^.*$/,
      methods: /^.*$/,
      strategy: true
    }]
    const repo = new MethodAccessControlRepository(policy)
    const known = { role: 'Manager', securable: { class: 'Foo', method: 'bar' } }
    const unknown = { role: uuid(), securable: { class: 'Foo', method: 'bar' } }

    expect(repo.explicitlyDenies(unknown)).to.be.false()
    expect(repo.permits(unknown)).to.be.false()

    expect(repo.explicitlyDenies(known)).to.be.false()
    expect(repo.permits(known)).to.be.true()
  })

  it('should explicitly deny', () => {
    const c = 'Foo'
    const m = 'bar'
    const r = 'Cowboy'
    const repo = new MethodAccessControlRepository([{
      classes: new RegExp(`^${c}$`),
      methods: new RegExp(`^${m}$`),
      roles: new RegExp(`^${r}$`),
      strategy: false
    }])

    const rcm = { role: r, securable: { class: c, method: m } }

    expect(repo.explicitlyDenies(rcm)).to.be.true()
    expect(repo.permits(rcm)).to.be.false()
  })

  it('should deny with a single denial', () => {
    const c = 'Foo'
    const m = 'bar'
    const r = 'Cowboy'
    const repo = new MethodAccessControlRepository([{
      classes: new RegExp(`^${c}$`),
      methods: new RegExp(`^${m}$`),
      roles: new RegExp(`^${r}$`),
      strategy: true
    }, {
      classes: new RegExp(`^${c}$`),
      methods: new RegExp(`^${m}$`),
      roles: new RegExp(`^${r}$`),
      strategy: true
    }, {
      classes: new RegExp(`^${c}$`),
      methods: new RegExp(`^${m}$`),
      roles: new RegExp(`^${r}$`),
      strategy: false
    }])

    const rcm = { role: r, securable: { class: c, method: m } }

    expect(repo.explicitlyDenies(rcm)).to.be.true()
    expect(repo.permits(rcm)).to.be.false()
  })

  it('should work with custom strategy', () => {
    const c = 'Account'
    const m = 'close'
    const manager = 'Manager'
    const owner = 'Owner'
    const strategy = it => it?.role === manager || it?.role === owner

    const repo = new MethodAccessControlRepository([{
      classes: new RegExp(`^${c}$`),
      methods: new RegExp(`^${m}$`),
      roles: new RegExp('^.*$'),
      strategy
    }])

    const rcm = { role: [manager, owner], securable: { class: c, method: m } }

    expect(repo.explicitlyDenies(rcm)).to.be.false()
    expect(repo.permits(rcm)).to.be.true()

    expect(repo.explicitlyDenies({ role: 'Teller', securable: { class: c, method: m } })).to.be.false()
    expect(repo.permits({ role: 'Teller', securable: { class: c, method: m } })).to.be.false()
  })

  it('should work with a custom strategy that uses data', () => {
    const c = 'Account'
    const m = 'close'
    const manager = 'MANAGER'
    const teller = 'TELLER'
    // Tellers can only close low-valued Accounts, and no one can close accounts on odd calendar days
    const balanceThreshold = 10000
    const strategy = ({ role, data }) => {
      if (role === teller && data?.account?.balance >= balanceThreshold) return false
      return data?.dayOfMonth % 2 === 0
    }

    const repo = new MethodAccessControlRepository([{
      classes: new RegExp(`^${c}$`),
      methods: new RegExp(`^${m}$`),
      strategy
    }])

    const account = { balance: 1 } // start testing with low-value accounts

    let dayOfMonth = 1 // test odd calendar days

    expect(repo.permits({
      role: manager,
      securable: { class: c, method: m },
      data: { dayOfMonth, account }
    })).to.be.false()
    expect(repo.permits({
      role: teller,
      securable: { class: c, method: m },
      data: { dayOfMonth, account }
    })).to.be.false()

    dayOfMonth = 2 // test even calendar days

    expect(repo.permits({
      role: manager,
      securable: { class: c, method: m },
      data: { dayOfMonth, account }
    })).to.be.true()
    expect(repo.permits({
      role: teller,
      securable: { class: c, method: m },
      data: { dayOfMonth, account }
    })).to.be.true()

    account.balance = balanceThreshold + 1 // test high value accounts

    expect(repo.permits({
      role: manager,
      securable: { class: c, method: m },
      data: { dayOfMonth, account }
    })).to.be.true()
    expect(repo.permits({
      role: teller,
      securable: { class: c, method: m },
      data: { dayOfMonth, account }
    })).to.be.false()

    dayOfMonth = 1

    expect(repo.permits({
      role: manager,
      securable: { class: c, method: m },
      data: { dayOfMonth, account }
    })).to.be.false()
    expect(repo.permits({
      role: teller,
      securable: { class: c, method: m },
      data: { dayOfMonth, account }
    })).to.be.false()
  })

  it('should work when one role of many is permitted', () => {
    const policy = [
      {
        roles: /^Manager$/,
        classes: /^.*$/,
        methods: /^.*$/,
        strategy: true
      },
      {
        roles: /^Teller$/,
        classes: /^Foo$/,
        methods: /^snafu$/,
        strategy: true
      }
    ]
    const repo = new MethodAccessControlRepository(policy)
    const rcm = { role: ['Teller', 'Manager'], securable: { class: 'Foo', method: 'bar' } }

    expect(repo.explicitlyDenies(rcm)).to.be.false()
    expect(repo.permits(rcm)).to.be.true()
  })

  it('should work when a role among many is denied', () => {
    const policy = [
      {
        roles: /^Dummy$/,
        classes: /^.*$/,
        methods: /^.*$/,
        strategy: false
      },
      {
        roles: /^Teller$/,
        classes: /^Foo$/,
        methods: /^bar$/,
        strategy: true
      }
    ]
    const repo = new MethodAccessControlRepository(policy)
    const rcm = { role: ['Teller', 'Dummy'], securable: { class: 'Foo', method: 'bar' } }

    expect(repo.explicitlyDenies(rcm)).to.be.true()
    expect(repo.permits(rcm)).to.be.false()
  })

  it('should work as intended in an app', function () {
    const highValueThreshold = 10000

    const policy = [{
      // Administrators can do anything
      roles: /^Administrator$/,
      strategy: true,
      classes: /^.+$/,
      methods: /^.+$/
    }, {
      // Trainees, Tellers & Managers can open or reopen accounts
      roles: /^Trainee|Teller|Manager$/,
      strategy: true,
      classes: /^AccountWith(InlineChecks|Decorators)$/,
      methods: /^(re)?open$/
    }, {
      // Only Managers can close high-value accounts
      strategy: ({ role, data }) => { // custom access control strategy function
        switch (role) {
          case 'Teller':
            return data?.balance < highValueThreshold
          case 'Manager':
            return true
          default: // Trainees or any other non-Administrator role
            return false
        }
      },
      classes: /^AccountWith(InlineChecks|Decorators)$/,
      methods: /^close$/
    }]

    const rbac = new MethodAccessControlRepository(policy)

    function checkSecurity ({ roles, clazz, method, data }) {
      if (!rbac.permits({ role: roles, securable: { class: clazz, method }, data })) {
        throw new AuthorizationError({ info: { roles, class: clazz, method, data } })
      }
    }

    let getCurrentCallerRoles // magic function that gets the roles of the current caller from some context

    // first, use manually written, inline checks in a class

    class AccountWithInlineChecks {
      static open ({ id, firstName, lastName }) {
        checkSecurity({ roles: getCurrentCallerRoles(), clazz: 'AccountWithInlineChecks', method: 'open', data: this })
        return new AccountWithInlineChecks({ id, firstName, lastName })
      }

      constructor ({ id, firstName, lastName }) {
        this.id = id
        this.firstName = firstName
        this.lastName = lastName
        this.balance = 0
        this.opened = new Date()
        this.closed = null
      }

      close () {
        checkSecurity({ roles: getCurrentCallerRoles(), clazz: 'AccountWithInlineChecks', method: 'close', data: this })
        this.closed = new Date()
      }

      reopen () {
        checkSecurity({
          roles: getCurrentCallerRoles(),
          clazz: 'AccountWithInlineChecks',
          method: 'reopen',
          data: this
        })
        this.opened = new Date()
        this.closed = null
      }
    }

    // next, use decoraters as an AOP-based solution

    // for simplicity, this decorator assumes only regular methods, not property get/set methods, are decorated
    const secured = function (clazz, methodName, descriptor) {
      const originalMethod = descriptor.value

      descriptor.value = function (...args) {
        checkSecurity({ roles: getCurrentCallerRoles(), clazz: clazz.name, method: methodName, data: this })
        return originalMethod.apply(this, args)
      }

      return descriptor
    }

    class AccountWithDecorators {
      @secured
      static open ({ id, firstName, lastName }) {
        return new AccountWithInlineChecks({ id, firstName, lastName })
      }

      constructor ({ id, firstName, lastName }) {
        this.id = id
        this.firstName = firstName
        this.lastName = lastName
        this.balance = 0
        this.opened = new Date()
        this.closed = null
      }

      @secured
      close () {
        this.closed = new Date()
      }

      @secured
      reopen () {
        this.opened = new Date()
        this.closed = null
      }
    }

    function expectSecurityToBeEnforced (clazz) {
      // ensure opening an account works for all roles

      getCurrentCallerRoles = () => ['Administrator']
      clazz.open({ id: 1, firstName: 'Jane', lastName: 'Doe' })

      getCurrentCallerRoles = () => ['Manager']
      clazz.open({ id: 1, firstName: 'Jane', lastName: 'Doe' })

      getCurrentCallerRoles = () => ['Trainee']
      clazz.open({ id: 1, firstName: 'Jane', lastName: 'Doe' })

      getCurrentCallerRoles = () => ['Teller']
      const account = clazz.open({ id: 1, firstName: 'Jane', lastName: 'Doe' })
      account.close()
      account.reopen()

      // make a high value account to set up test for closing accounts
      account.balance = highValueThreshold

      getCurrentCallerRoles = () => ['Administrator']
      account.close()
      account.reopen()

      getCurrentCallerRoles = () => ['Manager']
      account.close()
      account.reopen()

      getCurrentCallerRoles = () => ['Teller']
      expect(() => account.close()).to.throw()
      expect(account.closed).not.to.be.ok()

      getCurrentCallerRoles = () => ['Trainee']
      expect(() => account.close()).to.throw()
      expect(account.closed).not.to.be.ok()

      getCurrentCallerRoles = () => ['Manager']
      account.close()
      expect(account.closed).to.be.ok()
    }

    expectSecurityToBeEnforced(AccountWithInlineChecks)
    expectSecurityToBeEnforced(AccountWithDecorators)
  })
})
