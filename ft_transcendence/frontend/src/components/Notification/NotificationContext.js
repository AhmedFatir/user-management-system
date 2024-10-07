import React, { createContext, useState } from 'react';

export const NotificationContext = createContext();

export const NotificationProvider = ({ children }) => {
  const [hasNotification, setHasNotification] = useState(false);

  const clearNotification = () => {
    setHasNotification(false);
  };

  return (
    <NotificationContext.Provider value={{ hasNotification, setHasNotification, clearNotification }}>
      {children}
    </NotificationContext.Provider>
  );
};
