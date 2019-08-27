/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */

package com.microsoft.azure.management.keyvault.samples;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.keyvault.models.CertificateBundle;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.keyvault.KeyPermissions;
import com.microsoft.azure.management.keyvault.SecretPermissions;
import com.microsoft.azure.management.keyvault.Vault;

import com.microsoft.azure.management.resources.fluentcore.arm.Region;
import com.microsoft.azure.management.resources.fluentcore.utils.SdkContext;
import com.microsoft.rest.LogLevel;

import org.apache.http.ssl.SSLContextBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;
/**
 * Azure Key Vault sample for managing key vaults -
 *  - Create a key vault
 *  - Authorize an application
 *  - Update a key vault
 *    - alter configurations
 *    - change permissions
 *  - Create another key vault
 *  - List key vaults
 *  - Delete a key vault.
 */
public final class ManageKeyVault {

    /**
     * Main function which runs the actual sample.
     * @param azure instance of the azure client
     * @param clientId client id
     * @return true if sample runs successfully
     */
   
    
    public class ClientSecretKeyVaultCredential extends KeyVaultCredentials
    {
        private String clientId;
        private String clientKey;
    
        public ClientSecretKeyVaultCredential( String clientId, String clientKey ) {
            this.clientId = clientId;
            this.clientKey = clientKey;
        }
    
        @Override
        public String doAuthenticate(String authorization, String resource, String scope) {
            AuthenticationResult token = getAccessTokenFromClientCredentials(
                    authorization, resource, clientId, clientKey);
            return token.getAccessToken();
        }
    
        private AuthenticationResult getAccessTokenFromClientCredentials(
                String authorization, String resource, String clientId, String clientKey) {
            AuthenticationContext context = null;
            AuthenticationResult result = null;
            ExecutorService service = null;
            try {
                service = Executors.newFixedThreadPool(1);
                context = new AuthenticationContext(authorization, false, service);
                ClientCredential credentials = new ClientCredential(clientId, clientKey);
                Future<AuthenticationResult> future = context.acquireToken(
                        resource, credentials, null);
                result = future.get();
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                service.shutdown();
            }
    
            if (result == null) {
                throw new RuntimeException("authentication result was null");
            }
            return result;
        }
    }

    /**
     * Main entry point.
     * @param args the parameters
     */
    public static void main(String[] args) {
        String vaultUrl = "https://lpmsiauth.vault.azure.net/";
        System.out.println ("start of the app");
        try {

            //=============================================================
            // Authenticate

            //final File credFile = new File(System.getenv("AZURE_AUTH_LOCATION"));
            final File credFile =new File("C://Users/limarlow/Downloads/code/java/key-vault-java-manage-key-vaults/src/main/java/com/microsoft/azure/management/keyvault/samples/my.azureauth");
 
            Azure azure = Azure.configure()
                    .withLogLevel(LogLevel.BASIC)
                    .authenticate(credFile)                
                    .withDefaultSubscription();

            // Print selected subscription
            System.out.println("Selected subscription: " + azure.subscriptionId());

            //runSample(azure, ApplicationTokenCredentials.fromFile(credFile).clientId());
            String clientId= "ef97fdb9-8389-44be-ab78-bf7ebf09a8c3";
            String clientKey= "0b03314d-723b-4e5a-a04a-4d78b52d6d29";
            ManageKeyVault kv= new ManageKeyVault();
            KeyVaultCredentials kvCred = kv.new ClientSecretKeyVaultCredential(clientId,clientKey);
            KeyVaultClient client = new KeyVaultClient(kvCred);
            CertificateBundle certBundle = client.getCertificate(vaultUrl, "lpcertificate");
            byte[] certificate = certBundle.cer();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            X509Certificate certficateAzure= (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificate));
            //KeyPairGenerator keyGen = KeyPairGenerator.getInstance("pcks12");
            char[] pwdArray= "password".toCharArray();
            keyStore.load(null,pwdArray);
            keyStore.setCertificateEntry("lpcertificate", certficateAzure);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslConext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(),new SecureRandom());
            //SecretBundle secret = client.getSecret(vaultUrl, "connectionString");
            //System.out.println(secret.value());
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }
     private ManageKeyVault(){}
 
}
