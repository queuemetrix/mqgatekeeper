# mqgatekeeper
<h2>IBM MQ LDAP and Active Directory Authentication Exit</h2>
[Queuemetrix Pty Ltd](https://www.queuemetrix.com)
<h3>Overview</h3>
<p>
Gatekeeper is a security plugin for MQ and provides a secure way for clients to connect to an MQ queue manager. It uses a client authentication exit module to extend the functionality of MQ to provide a method for JMS and other types of client connections to be authenticated using standard LDAP Simple authentication.
</p>
<p>
The module itself is called a 'security channel exit' and is named libMQAuthLdap. The module is deployed to an MQ server and is used to protect client MQ connections by providing username and password authentication against an enterprises single sign-on (SSO) such as LDAPS or Microsoft's Active Directory.
</p>
<p>
Client passwords are protected during channel authentication by using standard MQ one way SSL encryption. 
</p>
<p>
The module provides a number of key security features such as,
</p>
<ul>
<li/>Username/password authentication performed using LDAP/S simple bind authentication.
<li/>Every channel can employ a different security profile
<li/>Auto fail-over to alternate LDAP/S server when one is not available
<li/>Supports Microsoft Active Directory (AD) LDAP
<li/>One, or two way SSL on the connecting MQ client channel to protect the password on the wire.
<li/>Supports LDAP group memberships such as an AD group
<li/>Supports IP address filtering (the rules file is compatible with the BlockIP2 rules file)
<li/>Client user id translation or pass-through for object level authorisations (OAM)
<li/>Multiple client API support
</ul>


