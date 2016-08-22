OpenVPN-Config-Generator
========================
OpenVPN-Config-Generator is made to help automate the process of creating OpenVPN configurations.

You can use one of the pre-built templates if your new to OpenVPN or you can build your own template to fit your needs.

Template File
-------------
Template files are written in JSON and have 4 keys in them. They are meta, client, server, and both. 

###client, server, both###
These 3 keys follow the same syntax rules. Keys in the client section will be put in the client's configuration files, keys in the server section will be put in the server's configuration file, and keys in both section will be put in both the client's and server's configuration files.

The keys value defines how the config file should be written


- **String**: The config file will be written with "*key value*"
- **Boolean**: When the value is set to true the key will be written alone to the config file.
- **Array**: The key will be written as "*key value*" for each value

**Example**:
```json
{
  "server": "10.8.8.0 255.255.255.0",
  "push": ["\"redirect-gateway def1 bypass-dhcp\"", "\"dhcp-option DNS 8.8.8.8\""],
  "duplicate-cn": true
}
```

**Output**:
```
server 10.8.8.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
duplicate-cn
```

###meta###
The meta section is used for information related to the build. The following keys are accepted:

- **savecerts**: If set to true this will save all the certs and keys used to generate the configurations.
- **embedkeys**: If set to true the keys and certs needed to run the configuration will be embed into the ovpn file. If false they will be referenced by filename.
- **tls-auth**: If set to true tls-auth will be configured for clients and servers.
- **keysize**: The size of the keys to be generated.
- **dhsize**: The size of the Diffie–Hellman parameters that will be generated.
