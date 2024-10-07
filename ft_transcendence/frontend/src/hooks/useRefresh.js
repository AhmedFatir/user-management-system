import React from 'react'
import axios from '../api/axios'
import useAuth from './useAuth'


const REFRESH_URL = 'auth/token/refresh'

const useRefresh = () => {
    const {setAuth} = useAuth()
    
    const refresh = async () => {
        const  response = await axios.post(
            REFRESH_URL,
             {},{withCredentials: true}
        );
        setAuth(prev => {
            // console.log(JSON.stringify(prev));
            // console.log(response.data.access);
            return{...prev, accessToken: response.data.access}
        });
        return response.data.access;
    }
  return refresh;
}

export default useRefresh