import React, { useContext } from 'react';
import './index.css';
import SideBar from './components/SideBar/SideBar';
import TopBar from './components/TopBar/TopBar';
import { createBrowserRouter, Outlet, RouterProvider } from 'react-router-dom';
import './App.css'
import Notification from './components/Notification/Notification';
import ToastContainer from './components/ReactToastify/ToastContainer';
import { UserContext, UserProvider } from './context/UserContext';
import BotIcon from './components/BotIcon/BotIcon'
import Draggable from 'react-draggable';
import useAuth from './hooks/useAuth';

const AppLayout = () => {
  const { userData, userDataLoading, userDataError } = useContext(UserContext);

  if (userDataLoading) {
    return <div>Loading...</div>; // 
  }

  if (userDataError) {
    return <div>Error loading user data: {userDataError.message}</div>; 
  }

  return (
    <div className='app'>
      <SideBar />
      
      <main className='main'>
        <TopBar />
        <div className='page-content'>
          <div className='content'>
            <Outlet />
          </div>
        </div>
      </main>
      <BotIcon />
      {/* <ToastContainer /> */}
    </div>
  );
};


export default AppLayout