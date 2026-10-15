import java.lang.reflect.Field;
public class SigAll {
  public static void main(String[] a) throws Exception {
    Class<?> c = Class.forName("sun.security.ssl.SignatureScheme");
    for (Object o : c.getEnumConstants()) System.out.println("  " + o);
    System.out.println("--- static fields ---");
    for (Field f : c.getDeclaredFields()) {
      if (f.getType() == c) System.out.println("  const " + f.getName());
    }
  }
}