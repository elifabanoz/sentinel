package io.sentinel.gateway.domain;

import org.springframework.stereotype.Service;

import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

@Service
public class DnsVerificationService {

    public boolean verifyTxtRecord(String domain, String expectedToken) {
        try {
            // JNDI: Java Naming and Directory Interface 
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("java.naming.provider.url", "dns:");

            InitialDirContext ctx = new InitialDirContext(env);

            Attributes attrs = ctx.getAttributes(domain, new String[]{"TXT"});
            javax.naming.directory.Attribute txtRecords = attrs.get("TXT");

            if (txtRecords == null) return false;

            for (int i = 0; i < txtRecords.size(); i++) {
                String record = txtRecords.get(i).toString();
                if (record.contains(expectedToken)) {
                    return true;
                }
            }
            return false;

        } catch (Exception e) {
            return false;
        }
    }
}
