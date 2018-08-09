package com.lzh.tools.StringHelper;

public class StringFormat {

    /*
    * 全角转半角
    * */
    public static String WholeToHalfAngle(String whole){
        if (whole.equals("")) {
            return whole;
        }

        char[] charArray = whole.toCharArray();
        for (int i = 0; i < charArray.length; i++) {
            if (charArray[i] == 12288) {
                charArray[i] =' ';
            } else if (charArray[i] >= ' ' &&
                    charArray[i]  <= 65374) {
                charArray[i] = (char) (charArray[i] - 65248);
            } else {

            }
        }
        return new String(charArray);
    }
    /*
    * 半角转全角
    * */
    public static String HalfToWholeAngle(String half){
        if (half.equals("")) {
            return half;
        }
        char[] cha = half.toCharArray();
        for (int i = 0; i < cha.length; i++) {
            if (cha[i] == 32) {
                cha[i] = (char) 12288;
            } else if (cha[i] < 127) {
                cha[i] = (char) (cha[i] + 65248);
            }
        }
        return new String(cha);
    }

    public static void main(String[] args) {
        System.out.print(WholeToHalfAngle("＄％２２１３＾＆＊％＊（）"));
        System.out.print(HalfToWholeAngle("23657354dhfghjghj"));
    }
}
