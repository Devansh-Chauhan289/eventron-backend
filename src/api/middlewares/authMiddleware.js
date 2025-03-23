import jwt from "jsonwebtoken"
import dotenv from "dotenv"

dotenv.config()

const authMiddleware = (req, res, next) => {
    const token = req.header("Authorization")?.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: "No token, authorization denied" })
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        req.user = decoded
        next()
    } catch (err) {
        // Logging for debugging purposes
        console.log("JWT Error:", err); 

        // Token expired error
        if (err.name === "TokenExpiredError") {
            return res.status(401).json({ msg: "Token has expired" })
        }
        
        // Invalid token error
        return res.status(401).json({ msg: "Token is not valid" })
    }
}

export { 
    authMiddleware 
}
