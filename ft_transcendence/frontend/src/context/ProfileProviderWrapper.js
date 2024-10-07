import React from 'react';
import { useParams } from 'react-router-dom';
import { ProfileProvider } from './ProfilContext';

const ProfileProviderWrapper = ({ children }) => {
  const { nameOfUser } = useParams(); 

  return (
    <ProfileProvider key={nameOfUser}>
      {children}
    </ProfileProvider>
  );
};

export default ProfileProviderWrapper;