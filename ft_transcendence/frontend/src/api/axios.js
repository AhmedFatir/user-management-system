import axios from 'axios'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const BASE_URL = BACKEND_URL

export default axios.create({
    baseURL: BASE_URL
})


export const axiosPrivate =  axios.create({
    baseURL: BASE_URL,
    headers : {
        'Content-Type' : 'application/json'
    }, 
    withCredentials: true
})