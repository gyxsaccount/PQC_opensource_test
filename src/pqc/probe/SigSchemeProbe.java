import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;

public class SigSchemeProbe {

    public static void main(String[] args) throws Exception {
        Class<?> clazz = Class.forName("sun.security.ssl.SignatureScheme");
        System.out.println("=== sun.security.ssl.SignatureScheme ===");
        Field[] fields = clazz.getDeclaredFields();
        for (Field f : fields) {
            if (f.getName().toUpperCase().contains("MLDSA") || f.getName().toUpperCase().contains("ED") 
                    || f.getName().equalsIgnoreCase("nameOf") || f.getName().contains("scheme")) {
                System.out.println("  field: " + f.getName() + " type=" + f.getType().getSimpleName());
            }
        }
        // enumerate enum constants
        if (clazz.isEnum()) {
            Object[] constants = clazz.getEnumConstants();
            System.out.println("  enum constants count=" + constants.length);
            for (Object c : constants) {
                String n = c.toString();
                if (n.toUpperCase().contains("MLDSA") || n.toUpperCase().contains("ED25519") || n.toUpperCase().contains("RSA")) {
                    System.out.println("    " + n);
                }
            }
        }
        // check how the scheme name field is named
        for (Method m : clazz.getDeclaredMethods()) {
            if (m.getName().toLowerCase().contains("name")) {
                System.out.println("  method: " + m.getName());
            }
        }
    }
}
