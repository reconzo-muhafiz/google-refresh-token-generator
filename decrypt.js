import "dotenv/config";
import crypto from "crypto";

const decrypt = (encrypted) => {
    const iv = Buffer.from(encrypted.iv, "hex");
    const encryptedText = Buffer.from(encrypted.data, "hex");

    const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(process.env.ENCRYPTION_KEY, "hex"), iv);

    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}

/**
 *       - - - - - BEFORE GOING FURTHER - - - - -
 *  Set the below variable to object you want to decrypt.
 * 
 */
const encrypted = {}

const decrypted = decrypt(encrypted);
console.log("Decrypted: ", decrypted);