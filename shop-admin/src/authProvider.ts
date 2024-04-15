import { AuthProvider, HttpError} from "react-admin";
import data from "./users.json";
import axios from 'axios'
/**
 * This authProvider is only for test purposes. Don't use it in production.
 */
export const authProvider: AuthProvider = {
  login: ({ username, password }) => {
    let data = JSON.stringify({
      "username": username,
      "password": password
    });
  
    let config = {
      method: 'POST',
      url: 'http://127.0.0.1:5000/user/login',
      headers: { 
        'Content-Type': 'application/json'
      },
      data : data
    };
  
    return axios.request(config)
      .then((response) => {
        if (response.status === 200) {
          console.log(JSON.stringify(response.data.token));
          let token = response.data.token;
          localStorage.setItem("token", token);
          return axios.get('http://127.0.0.1:5000/profiles', {
            headers: { 'Authorization': `Bearer ${token}` }
          });
        } else {
          throw new Error("Login failed");
        }
      })
      .then((profileResponse) => {
        if (profileResponse.data.role !== 'admin') {
          throw new Error("Unauthorized access");
        }
      })
      .catch((error) => {
        console.error(error.message || "An error occurred");
        // Handle the error properly here
      });
  },
  logout: () => {
    localStorage.removeItem("token");
    return Promise.resolve();
  },
  checkError: () => Promise.resolve(),
  checkAuth: () =>
    localStorage.getItem("token") ? Promise.resolve() : Promise.reject(),
  getPermissions: () => {
    return Promise.resolve(undefined);
  },
  getIdentity: () => {
    const token = localStorage.getItem("token");
    let config = {
      method: 'get',
      maxBodyLength: Infinity,
      url: 'http://127.0.0.1:5000/profiles',
      headers: { 
        'Authorization': `Bearer ${token}`
      }
    };
    
    axios.request(config)
    .then((response) => {
      console.log(JSON.stringify(response.data));
      if(response.data.role=='admin'){
        let data=JSON.stringify(response.data);
        const user = data ? JSON.parse(data) : null;
        return Promise.resolve(data);
      }else{
        throw new Error("Unauthorized access");
      }
    })
    .catch((error) => {
      throw new Error("Unauthorized access");
    });
  },
};

export default authProvider;


