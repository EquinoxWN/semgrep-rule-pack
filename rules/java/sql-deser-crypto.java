// Test fixture for semgrep --test: annotated examples, never compiled or run.
import java.beans.XMLDecoder;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.crypto.Cipher;

class Fixture {
    void sql(Connection conn, String id) throws Exception {
        Statement st = conn.createStatement();
        // ruleid: java-sql-string-building
        st.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
        // ruleid: java-sql-string-building
        st.executeUpdate(String.format("DELETE FROM users WHERE id = '%s'", id));
        String q = "SELECT * FROM users WHERE name = '" + id + "'";
        // ruleid: java-sql-string-building
        conn.prepareStatement(q);
        // ok: java-sql-string-building
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        // ok: java-sql-string-building
        ps.executeQuery();
        // ok: java-sql-string-building
        st.executeQuery("SELECT count(*) FROM users");
    }

    Object deser(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: java-unsafe-deserialization
        Object a = ois.readObject();
        XMLDecoder dec = new XMLDecoder(in);
        // ruleid: java-unsafe-deserialization
        Object b = dec.readObject();
        ObjectInputStream filtered = new ObjectInputStream(in);
        filtered.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.Dto;!*"));
        // ok: java-unsafe-deserialization
        Object c = filtered.readObject();
        return a == null ? b : c;
    }

    void crypto() throws Exception {
        // ruleid: java-weak-crypto
        MessageDigest.getInstance("MD5");
        // ruleid: java-weak-crypto
        MessageDigest.getInstance("SHA-1");
        // ruleid: java-weak-crypto
        Cipher.getInstance("AES");
        // ruleid: java-weak-crypto
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: java-weak-crypto
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ok: java-weak-crypto
        MessageDigest.getInstance("SHA-256");
        // ok: java-weak-crypto
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}
