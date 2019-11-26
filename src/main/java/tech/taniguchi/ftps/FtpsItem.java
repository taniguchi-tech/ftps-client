package tech.taniguchi.ftps;

/**
 * FtpsClientで接続先FTPSサーバーのディレクトリー、ファイルリスト情報の取得に使用します。
 *
 * @author    d.taniguchi
 * @see       <a href="https://blog.taniguchi.tech/archives/31">taniguchi web logs<br>
 *            Apache Commons Net 3.6 FTPSClientが動かない！！諦めかけたそのとき、希望の光が見えることはなかった</a>
 */
public class FtpsItem {

    public enum TypeEnum {
        /** . */
        CURRENT_DIRECTORY,
        /** .. */
        PARENT_DIRECTORY,
        /** ディレクトリ */
        DIRECTORY,
        /** ファイル */
        FILE
    }

    private TypeEnum typeEnum;
    private String name;

    public TypeEnum getTypeEnum() {
        return typeEnum;
    }
    void setTypeEnum(TypeEnum typeEnum) {
        this.typeEnum = typeEnum;
    }
    public String getName() {
        return name;
    }
    void setName(String name) {
        this.name = name;
    }
}
