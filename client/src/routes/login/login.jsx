import { useState } from "react";
import "./login.scss";
import { Link, useNavigate } from "react-router-dom";
import apiRequest from "../../lib/apiRequest.js";

function Login() {
  const [error , setError] = useState("")
  const [isLoading , setIsLoading] = useState(false)


  const navigate = useNavigate()
  const handleSubmit = async (e) =>{
    e.preventDefault()
    setIsLoading(true);
    setError("")
    const formData = new FormData(e.target);

    const username = formData.get("username");
    const email = formData.get("email");
    const password = formData.get("password");
  

    try {

      const res = await apiRequest.post("auth/login" , {
        username , password,
      })   
      console.log(res);
       
      
      //navigate("/login");
    }catch(err){
      console.log(err);
      setError(err.response.data.message);
    } finally {
      setIsLoading(false)
    }

  }
  return (
    <div className="login">
      <div className="formContainer">
        <form onSubmit={handleSubmit}>
          <h1>Welcome back</h1>
          <input name="username" required minLength={3} maxLength={25} type="text" placeholder="Username" />
          <input name="password" required minLength={5} maxLength={25} type="password" placeholder="Password" />
          <button disabled = {isLoading}>Login</button>
          {error && <span>{error}</span>}
          <Link to="/register">{"Don't"} you have an account?</Link>
        </form>
      </div>
      <div className="imgContainer">
        <img src="/bg.png" alt="" />
      </div>
    </div>
  );
}

export default Login;