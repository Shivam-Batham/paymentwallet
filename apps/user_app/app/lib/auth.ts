import db from "@repo/db/client";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import GoogleProvider from "next-auth/providers/google";

export const authOptions = {
    providers: [
        CredentialsProvider({
            name: 'Credentials',
            credentials: {
                phone: { label: "Phone number", type: "text", placeholder: "1231231231", required: true },
                password: { label: "Password", type: "password", required: true }
            },
            async authorize(credentials: any) {
                const hashedPassword = await bcrypt.hash(credentials.password, 10)
                const existingUser = await db.user.findFirst({
                    where: {
                        number: credentials.phone
                    }
                })

                if (existingUser) {
                    const passwordValidation = await bcrypt.compare(this.credentials.password, existingUser.password);
                    if (passwordValidation) {
                        return {
                            id: existingUser.id.toString(),
                            name: existingUser.name,
                            email: existingUser.email,
                            number: existingUser.number
                        }
                    }
                    return null;
                }
                try {
                    const user = await db.user.create({
                        data: {
                            name: credentials.name,
                            number: credentials.phone,
                            password: hashedPassword,
                            email: credentials.email,
                        }
                    })
                    return {
                        id: user.id.toString(),
                        name: user.name,
                        email: user.email,
                        number:user.number
                    }
                }catch(err){
                    console.log("error in auth",err);
                }
                return null;
            }

        }),
        GoogleProvider({
            clientId: process.env.GOOGLE_CLIENT_ID || "",
            clientSecret: process.env.GOOGLE_CLIENT_SECRET || ""
        })
    ],
    secret:process.env.JWT_SECRET || "DummySecret",
    callback:{
        async session({token,session}:any){
            session.user.id=token.sub

            return session;
        }
    }
}