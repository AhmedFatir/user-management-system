import React, { useEffect, useState } from 'react'
import useAuth from '../../hooks/useAuth'
import useRefresh from '../../hooks/useRefresh'
import AppLayout from '../../index'
import { Outlet } from 'react-router-dom'
import Lottie from 'lottie-react';
import loadingAnimation from '../OauthTwo/loading-animation.json'




const PersistLogin = () => {
    const [isLoading, setIsLoading] = useState(true);
    const refresh = useRefresh()
    const { auth } = useAuth()

    useEffect(() => {
        const checkToken = async () => {
            try {
                await refresh(); 
            } catch (e) {
                console.log(e)
            } finally {
                setIsLoading(false)
            }
        }
        !auth?.accessToken ?  checkToken() : setIsLoading(false);
        // if(!auth?.accessToken) {
        //     checkToken()
        // }
    }, [])
    return (
        <>
            {isLoading ?           
            <div className='oauth-loading'>
                {console.log("i am loading effect nigga")}
                <Lottie animationData={loadingAnimation} style={{ width: 400, height: 400 }} />
            </div>
            : 
            <Outlet />} 
        </>
    )
}

export default PersistLogin