import React, {useContext} from 'react';
import './SideBar.css';
import { assets } from '../../assets/assets';
import { Link, useLocation } from 'react-router-dom';
import Icon from '../../assets/Icon/icons';
import useSidebarData from './SideBarData';
import { useNavigate } from 'react-router-dom';
import useAuth from '../../hooks/useAuth';
import axios from 'axios';
import { clientSocketContext } from '../../pages/Chat/usehooks/ChatContext';
import { useTranslation } from 'react-i18next'


const SideBar = () => {
  const location = useLocation().pathname;
  const SideBarData = useSidebarData();
  const navigate = useNavigate();
  const {auth, setAuth} = useAuth();
  const { t } = useTranslation();
  const { stateValue: clientSocket, botSocket } = useContext(clientSocketContext);

  const handleLogout = async () => {
    try {
      const response = await axios.post(`${process.env.REACT_APP_BACKEND_URL}/auth/logout/`, {}, {
        headers: {
          'Authorization': `Bearer ${auth.accessToken}`, 
        },
        withCredentials: true,
      });
    } catch (error) {
      console.error('Error logging out:', error.response ? error.response.data : error.message);
    }
    
    if (clientSocket)
      clientSocket.close();
    if (botSocket)
      botSocket.close();
    setAuth(null);
    navigate('/auth');
  };
  
  

  return (
    <div className='sidebar-container'>
      <div className='sidebar-logo-container'>
        <img src={assets.logo} alt='Pongy Logo' />
      </div>
      <nav className='nav-container'>
        <ul className='nav-menu-items'>
          {SideBarData.map((item, index) => (
            <li key={index} className={`navbar-toggle ${location === item.path ? 'active' : ''}`}>
              <Link to={item.path} className='navbar-toggle-link'>
                {item.icon}
                <span>{item.title}</span>
              </Link>
            </li>
          ))}
          <li className='navbar-toggle-logout'>
            <div className='logout-sep'>
              <img src={assets.sep} alt='separator' />
            </div>
            <div className='logout-link' onClick={handleLogout}>
              <Icon name='logout' className='navbar-toggle-icon' />
              <span>{t('Logout')}</span>
            </div>
          </li>
        </ul>
      </nav>
    </div>
  );
};

export default SideBar;
