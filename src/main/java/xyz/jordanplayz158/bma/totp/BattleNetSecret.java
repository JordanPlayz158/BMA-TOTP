package xyz.jordanplayz158.bma.totp;

import org.apache.commons.codec.binary.Base16;
import org.apache.commons.codec.binary.Base32;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Objects;

public class BattleNetSecret {
    public static void main(String[] args) throws DocumentException {
        if(args.length != 1) {
            System.out.println("You must provide the file argument and only the file argument to run this application (the file path can contain NO spaces)!");
            return;
        }

        File file = new File(args[0]);

        if(!file.exists()) {
            System.out.println("The path provided does not exist.");
            return;
        }

        if(!file.isFile()) {
            System.out.println("The path does not point to a file.");
            return;
        }

        if(!file.canRead()) {
            System.out.println("This application does not have permission to read the file.");
            return;
        }

        SAXReader reader = new SAXReader();
        Document root = reader.read(file);

        Element map = root.selectSingleNode("//map").getDocument().getRootElement();
        Iterator<Element> elementIterator = map.elementIterator();

        String hash = null;
        while(elementIterator.hasNext()) {
            Element element = elementIterator.next();

            if(!Objects.equals(element.attribute("name").getText(), "com.blizzard.bma.AUTH_STORE.HASH")) {
                continue;
            }

            hash = element.getStringValue();

            break;
        }

        if(hash == null) {
            System.out.println("The XML document did not contain an element named 'com.blizzard.bma.AUTH_STORE.HASH' inside 'map'");
            return;
        }

        final int[] mask = {57,142,39,252,80,39,106,101,
                96,101,176,229,37,244,192,108,
                4,198,16,117,40,107,142,122,
                237,165,157,169,129,59,93,214,
                200,13,47,179,128,104,119,63,
                165,155,164,124,23,202,108,100,
                121,1,92,29,91,139,143,107,
                154};

        byte[] hashBytes = hash.getBytes(StandardCharsets.UTF_8);

        Base16 base16 = new Base16(true);
        byte[] hashBytesBase16Decoded = base16.decode(hashBytes);

        StringBuilder unmaskingStringBuilder = new StringBuilder();

        for (int i = 0 ; i < hashBytesBase16Decoded.length; i++) {
            int hashByte = hashBytesBase16Decoded[i];
            int maskByte = mask[i];

            // This is my only complaint with this solution, using the python script as a reference
            // I see no reason why this is needed but after many hours of investigation
            // some bytes were negative and offset by EXACTLY 256 and this fixes it
            if(hashByte < 0) {
                hashByte += 256;
            }

            int character = (hashByte ^ maskByte);

            unmaskingStringBuilder.append((char) character);
        }

        String unmasking = unmaskingStringBuilder.toString();

        byte[] secretHexBytes = unmasking.substring(0, 40).getBytes(StandardCharsets.UTF_8);
        String secretHex = new String(secretHexBytes);

        Base32 base32 = new Base32();
        byte[] secretBytes = base32.encode(base16.decode(secretHex));
        String secret = new String(secretBytes);

        String serial = unmasking.substring(40);

        System.out.println("secret (hex): " + secretHex);
        System.out.println("secret: " + secret);
        System.out.println("serial: " + serial);
        System.out.printf("otpauth://totp/Battle.net:%s?secret=%s&issuer=Battle.net&digits=8%n", "BMA", secret);
    }
}