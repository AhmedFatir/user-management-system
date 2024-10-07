import React from 'react';
import { useTranslation } from 'react-i18next'

const ErrorModal = ({onClose }) => {
    const { t } = useTranslation();
    const message = t("Please select a background before launching the game.");
    const handleOverlayClick = (e) => {
      if (e.target === e.currentTarget) {
        onClose();
      }
    };
  
    return (
      <div className="modal-overlay" onClick={handleOverlayClick}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()}>
          <p className='modal-message'>{message}</p>
        </div>
      </div>
    );
}
export default ErrorModal;
