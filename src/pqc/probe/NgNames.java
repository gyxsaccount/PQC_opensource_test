import org.bouncycastle.tls.NamedGroup;

public class NgNames {
    public static void main(String[] a) {
        int[] ids = {NamedGroup.X25519MLKEM768, NamedGroup.MLKEM768, NamedGroup.MLKEM512,
                NamedGroup.MLKEM1024, NamedGroup.SecP256r1MLKEM768, NamedGroup.OQS_mlkem768,
                NamedGroup.x25519, NamedGroup.secp256r1};
        for (int id : ids) {
            System.out.println(id + " standard=" + NamedGroup.getStandardName(id)
                    + " name=" + NamedGroup.getName(id) + " text=" + NamedGroup.getText(id));
        }
    }
}
