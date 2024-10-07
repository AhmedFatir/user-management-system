import React from 'react';
import { useTranslation } from 'react-i18next';
import Icon from '../../assets/Icon/icons';

const useSidebarData = () => {
    const { t } = useTranslation();

    return [
        {
            title: t('Dashboard'),
            path: '/',
            icon: <Icon name='dashboard' className='navbar-toggle-icon'/>
        },
        {
            title: t('Game'),
            path: '/game',
            icon: <Icon name='game' className='navbar-toggle-icon'/>
        },
        {
            title: t('Chat'),
            path: '/chat',
            icon: <Icon name='chat' className='navbar-toggle-icon'/>
        },
        {
            title: t('Tournament'),
            path: '/tournament',
            icon: <Icon name='tournament' className='navbar-toggle-icon'/>
        },
        {
            title: t('Leaderboard'),
            path: '/leaderboard',
            icon: <Icon name='leaderboard' className='navbar-toggle-icon'/>
        },
        {
            title: t('Setting'),
            path: '/setting',
            icon: <Icon name='setting' className='navbar-toggle-icon'/>
        }
    ];
};

export default useSidebarData;
