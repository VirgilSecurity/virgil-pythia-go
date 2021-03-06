# Virgil Pythia Go SDK
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-pythia-go.png?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-pythia-go)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [SDK Features](#sdk-features) | [Install and configure SDK](#install-and-configure-sdk) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides an SDK which allows you to communicate with Virgil Pythia Service and implement Pythia protocol for the following use cases:
- **Breach-proof password**. Pythia is a technology that gives you a new, more secure mechanism that "breach-proofs" user passwords in your database and lessens the security risks associated with weak passwords by providing cryptographic leverage for the defender (by eliminating offline password cracking attacks), detection for online attacks, and key rotation to recover from stolen password databases.
- **BrainKey**. User's Private Key which is based on user's password. BrainKey can be easily restored and is resistant to online and offline attacks.

In both cases you get the mechanism which assures you that neither Virgil nor attackers know anything about user's password.

## SDK Features
- communicate with Virgil Pythia Service
- manage your Pythia application credentials
- create, verify and update user's breach-proof password
- generate user's BrainKey
- use [Virgil Crypto Pythia library][_virgil_crypto_pythia]

## Install and configure SDK

The Virgil Pythia Go SDK is provided as a package named virgil-pythia-go. The package is distributed via GitHub.
The package is available for Go 1.10 or newer.

### Install SDK Package

Virgil Pythia SDK uses the Virgil Crypto library to perform cryptographic operations. The Virgil Pythia Go SDK is provided as a package named virgil-pythia-go. The package is distributed via GitHub.
The package is available for Go 1.10 or newer.

#### Step #1. Install a Crypto Library (C++)

There two ways to install the Crypto Library:

**The first**, if you are building from sources, install prerequisites as described [here](https://github.com/VirgilSecurity/virgil-crypto/#build) and then install the library:

```bash
go get -u -d gopkg.in/virgilsecurity/virgil-crypto-go.v5
cd $(go env GOPATH)/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5
make
```

**The second**, if you use Linux x64 or Darwin x64 architecture, you can use the pre-built crypto binaries
for Linux:
```bash
CRYPTO_LIB=virgil-crypto-2.4.4-go-linux-x86_64.tgz
```
or for MacOS:
```bash
CRYPTO_LIB=virgil-crypto-2.4.4-go-darwin-17.5-x86_64.tgz
```

and then install the library:

```bash
go get -u -d gopkg.in/virgilsecurity/virgil-crypto-go.v5
wget https://cdn.virgilsecurity.com/virgil-crypto/go/$CRYPTO_LIB
tar -xvf $CRYPTO_LIB --strip-components=1 -C $(go env GOPATH)/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5/
```

#### Step #2. Installing Virgil Pythia Go package

Install Pythia SDK library with the following code:
```bash
go get -u github.com/VirgilSecurity/virgil-pythia-go
```

### Configure SDK
When you create a Pythia Application on the [Virgil Dashboard][_dashboard] you will receive Application credentials including: Proof Key and App ID. Specify your Pythia Application and Virgil account credentials in a Pythia SDK class instance.
These credentials are used for the following purposes:
- generating a JWT token that is used for authorization on the Virgil Services
- creating a user's breach-proof password

Here is an example of how to specify your credentials SDK class instance:
```go
package main

import (
  "github.com/VirgilSecurity/virgil-pythia-go"
)


func main() {
  // here set your Virgil account and Pythia Application credentials
  ctx, err := pythia.CreateContext("API_KEY", "API_KEY_ID", "APP_ID", "PK.1.PROOF_KEY")
  if err != nil{
    panic(err)
  }

  pythia := pythia.New(ctx)
}
```

## Usage Examples

### Breach-proof password

Virgil Pythia SDK lets you easily perform all the necessary operations to create, verify and update user's breach-proof password without requiring any additional actions and use Virgil Crypto library.

First of all, you need to set up your database to store users' breach-proof passwords. Create additional columns in your database for storing the following parameters:
<table class="params">
<thead>
		<tr>
			<th>Parameters</th>
			<th>Type</th>
			<th>Size (bytes)</th>
			<th>Description</th>
		</tr>
</thead>

<tbody>
<tr>
	<td>salt</td>
	<td>blob</td>
	<td>32</td>
	<td> Unique random string that is generated by Pythia SDK for each user</td>
</tr>

<tr>
	<td>deblindedPassword</td>
	<td>blob </td>
	<td>384 </td>
	<td>user's breach-proof password</td>
</tr>

<tr>
	<td>version</td>
	<td>int </td>
	<td>4 </td>
	<td>Version of your Pythia Application credentials. This parameter has the same value for all users unless you generate new Pythia credentials on Virgil Dashboard</td>
</tr>

</tbody>
</table>

Now we can start creating breach-proof passwords for users. Depending on the situation, you will use one of the following Pythia SDK functions:
- `CreateBreachProofPassword` is used to create a user's breach-proof password on your Application Server.
- `VerifyBreachProofPassword` is used to verify a user's breach-proof password.

#### Create Breach-Proof Password

Use this flow to create a new breach-proof password for a user.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in into your system to implement Pythia. You can go through your database and create breach-proof user passwords at any time.

So, in order to create a user's breach-proof password for a new database or available one, go through the following operations:
- Take a user's password (or its hash or whatever you use) and pass it into a `CreateBreachProofPassword` function in SDK on your Server side.
- Pythia SDK generates unique user's **salt** and **version** (which is the same for every user until you change your app credentials on Pythia Service). You need to store user's salt and version in your database in associated columns created on previous step.
- Pythia SDK blinds a password and sends a request to Pythia Service to get a **transformed blinded password**.
- Pythia SDK de-blinds the transformed blinded password into a user's **deblinded password** (that we call **breach-proof password**).

```go
// create a new Breach-proof password using user's password or its hash
pwd, err := pythia.CreateBreachProofPassword("USER_PASSWORD")

if err != nil{
panic(err)
}
// save Breach-proof password parameters into your users DB
fmt.Println(pwd.Salt, pwd.DeblindedPassword, pwd.Version)
```

After performing `CreateBreachProofPassword` function you get previously mentioned parameters (`Salt`, `deblindedPassword`, `version`), save these parameters into corresponding columns in your database.

Check that you updated all database records and delete the now unnecessary column where user passwords were previously stored.

#### Verify Breach-Proof Password

Use this flow on Server side when a user already has his or her own breach-proof password in your database. You will have to pass his or her password into an `VerifyBreachProofPassword` function:

```go
//get user's Breach-proof password parameters from your users DB

...
// calculate user's Breach-proof password parameters
// compare these parameters with parameters from your DB
err = pythia.VerifyBreachProofPassword("USER_PASSWORD", pwd, false)

if err != nil{
//authentication failed ot throttle reached
}
```

The difference between the `VerifyBreachProofPassword` and `CreateBreachProofPassword` functions is that the verification of Pythia Service is optional in `VerifyBreachProofPassword` function, which allows you to achieve maximum performance when processing data. You can turn on a proof step in `VerifyBreachProofPassword` function if you have any suspicions that a user or Pythia Service were compromised.

#### Update breach-proof passwords

This step will allow you to use an `updateToken` in order to update users' breach-proof passwords in your database.

> Use this flow only if your database was COMPROMISED.

How it works:
- Access your [Virgil Dashboard][_dashboard] and press the "My Database Was Compromised" button.
- Pythia Service generates a special updateToken and new Proof Key.
- You then specify new Pythia Application credentials in the Pythia SDK on your Server side.
- Then you use `UpdateBreachProofPassword` function to create new breach-proof passwords for your users (you don't need to regenerate user's password).
- Finally, you save the new breach-proof passwords into your database.

Here is an example of using the `UpdateBreachProofPassword` function:
```go
//get previous user's VerifyBreachProofPassword parameters from a compromised DB

...

// set up an updateToken that you got on the Virgil Dashboard
// update previous user's deblindedPassword and version, and save new one into your DB
updatedPwd, err := pythia.UpdateBreachProofPassword("UT.1.2.UPDATE_TOKEN", pwd)
fmt.Println(updatedPwd.DeblindedPassword, updatedPwd.Version)
```

### BrainKey

*PYTHIA* Service can be used directly as a means to generate strong cryptographic keys based on user's **password** or other secret data. We call these keys the **BrainKeys**. Thus, when you need to restore a Private Key you use only user's Password and Pythia Service.

In order to create a user's BrainKey, go through the following operations:
- Register your E2EE application on [Virgil Dashboard][_dashboard] and get your app credentials
- Generate your API key or use available
- Set up **JWT provider** using previously mentioned parameters (**App ID, API key, API key ID**) on the Server side
- Generate JWT token with **user's identity** inside and transmit it to Client side (user's side)
- On Client side set up **access token provider** in order to specify JWT provider
- Setup BrainKey function with access token provider and pass user's password
- Send BrainKey request to Pythia Service
- Generate a strong cryptographic keypair based on a user's password or other user's secret


#### Generate BrainKey based on user's password
```go
package main

import (
    "github.com/VirgilSecurity/pythia-go"
    "gopkg.in/virgilsecurity/virgil-crypto-go.v5"
    "gopkg.in/virgil.v5/sdk"
    "time"
    "fmt"
)

func main(){

    // Initialize and create an instance of BrainKey class
    ctx, err := pythia.CreateBrainKeyContext(accessTokenProvider)
    if err != nil {
        panic(err)
    }
    brainkey := pythia.NewBrainKey(ctx)

    // Generate default public/private keypair which is Curve ED25519
    // If you need to generate several BrainKeys for the same password,
    // use different IDs.
    keypair, err := brainkey.GenerateKeypair("Your password","Optional BrainKey id")
    if err != nil {
        panic(err)
    }

}
```

#### Generate BrainKey based on unique URL
The typical BrainKey implementation uses a password or concatenated answers to security questions to regenerate the user’s private key. But a unique session link generated by the system admin can also do the trick.

This typically makes the most sense for situations where it’s burdensome to require a password each time a user wants to send or receive messages, like single-session chats in a browser application.

Here’s the general flow of how BrainKey can be used to regenerate a private key based on a unique URL:
- When the user is ready to begin an encrypted messaging session, the application sends the user an SMS message
- The SMS message contains a unique link like https://healthcare.app/?session=abcdef13803488
- The string 'abcdef13803488' is used as a password for the private key regeneration
- By clicking on the link, the user immediately establishes a secure session using their existing private key regenerated with Brainkey and does not need to input an additional password

Important notes for implementation:
- The link is one-time use only. When the user clicks on the link, the original link expires and cannot be used again, and so a new link has to be created for each new chat session.
- All URL links must be short-lived (recommended lifetime is 1 minute).
- The SMS messages should be sent over a different channel than the one the user will be using for the secure chat session.
- If you’d like to add additional protection to ensure that the person clicking the link is the intended chat participant, users can be required to submit their name or any other security question. This answer will need to be built in as part of the BrainKey password.

```go
...
    keypair, err := brainkey.GenerateKeypair("abcdef13803488","Optional User SSN")
    if err != nil {
        panic(err)
    }

    }
...
```
> Note! if you don't need to use additional parameters, like "Optional User SSN", you can just omit it: `keypair, err := brainkey.GenerateKeypair("abcdef13803488")`


## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

* [Breach-Proof Password][_pythia_use_case] Use Case
* [Brain Key][_brain_key_use_case] Use Case
* [The Pythia PRF Service](https://eprint.iacr.org/2015/644.pdf) - foundation principles of the protocol
* [Virgil Security Documentation][_documentation]

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).

[_virgil_crypto_pythia]: https://github.com/VirgilSecurity/pythia
[_brain_key_use_case]: https://developer.virgilsecurity.com/docs/use-cases/v1/brainkey
[_pythia_use_case]: https://developer.virgilsecurity.com/docs/go/use-cases/v1/breach-proof-password
[_documentation]: https://developer.virgilsecurity.com/
[_dashboard]: https://dashboard.virgilsecurity.com/
