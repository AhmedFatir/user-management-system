import React from 'react';
import { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import Icon from '../../assets/Icon/icons';
import './languageSelector.css'
import i18n from '../../i18n'

const LanguageSelector = () => {
  const { i18n } = useTranslation();
  const dropdownLanguageRef = useRef(null);
  const [isLanguageActive, setIsLanguageActive] = useState(false);
  const [selectedLanguage, setSelectedLanguage] = useState({
    code: localStorage.getItem('i18nextLng') || 'en',
    label: localStorage.getItem('i18nextLnge') || 'EN',
  });


  const toggleDropdown = () => {
    setIsLanguageActive(prevState => !prevState);
  };


  const changeLanguage = (code, label) => {

      i18n.changeLanguage(code);
      localStorage.setItem('i18nextLng', code);
      localStorage.setItem('i18nextLnge', label);
      setSelectedLanguage({ code, label});
      setIsLanguageActive(false);
  };

  const handleClickOutsideLanguage = (event) => {
    if (dropdownLanguageRef.current && !dropdownLanguageRef.current.contains(event.target)) {
      setIsLanguageActive(false);
    }
  };

  useEffect(() => {
    document.addEventListener('mousedown', handleClickOutsideLanguage);

    return () => {
      document.removeEventListener('mousedown', handleClickOutsideLanguage);
    };
  }, []);
  return (
    <div className='dropDwonLanguageContainer'>
      <button onClick={toggleDropdown} className="languageButton">
        <Icon name={selectedLanguage.label} className='flagIcon'/> 
        {selectedLanguage.label}
      </button>
      <div ref={dropdownLanguageRef} className={isLanguageActive ? "dropDwonLanguage LanguageActive" : "dropDwonLanguage"}>
        <div className='dropListLanguage'>
          <p className='list' onClick={() => changeLanguage('en', 'EN')}>
            <Icon name='EN' className='flagIcon'/> English 
          </p>
          <p className='list' onClick={() => changeLanguage('fr', 'FR')}>
            <Icon name='FR' className='flagIcon'/>  Français
          </p>
          <p className='list' onClick={() => changeLanguage('es', 'ES')}>
            <Icon name='ES' className='flagIcon'/>  Español
          </p>
        </div>
      </div>
    </div>
  );
};

export default LanguageSelector;