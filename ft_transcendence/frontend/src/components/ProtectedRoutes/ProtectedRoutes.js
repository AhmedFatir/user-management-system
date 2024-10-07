import React from 'react'
import useAuth from '../../hooks/useAuth'
import { useLocation, Navigate, Outlet } from 'react-router-dom'
import AppLayout from '../../index'

const ProtectedRoutes = () => {
    const {auth} = useAuth()
    const location = useLocation()
    // console.log("protected routes")
    // console.log(auth.accessToken); 
    return (
        auth?.accessToken ? <Outlet/> : <Navigate to='/auth' state={{from:location}} replace/>
    )
}

export default ProtectedRoutes