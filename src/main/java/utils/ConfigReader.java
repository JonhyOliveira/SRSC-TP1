package utils;

import java.io.*;
import java.util.Properties;
import java.util.Scanner;

public class ConfigReader extends Reader {

    private final Scanner s;
    private final String searchTag;

    public ConfigReader(InputStream fis, String tag) {
        this.s = new Scanner(fis);
        this.searchTag = tag;
    }

    @Override
    public int read(char[] cbuf, int off, int len) throws IOException {
        String r = "";
        String tag = "";
        int totalRead = 0;

        while (!tag.equals(searchTag)) {
            // System.out.println(r);
            while (!r.matches("^<[a-zA-Z0-9-.:]+>") && s.hasNext()) {
                // System.out.printf("no match: '%s'\n", r);
                r = s.nextLine();
            }

            if (!s.hasNext())
                return -1;

            tag = r.substring(1, r.length() - 1);
            // System.out.println("found tag = " + tag);

            r = s.nextLine();
            if (! tag.equals(searchTag))
                continue;

            while (!r.contains("</" + tag + ">") && s.hasNext() && len > 0) {
                CharArrayReader car = new CharArrayReader((r.split("//")[0].trim() + "\n").toCharArray());
                int read = car.read(cbuf, off, len);
                off += read;
                len -= read;
                totalRead += read;
                r = s.nextLine();
            }

            if (!s.hasNext())
                return totalRead > 0 ? totalRead : -1;
        }

        return totalRead;
    }

    @Override
    public void close() throws IOException {
        s.close();
    }

}
