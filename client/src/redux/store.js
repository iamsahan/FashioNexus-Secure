import { combineReducers, configureStore } from '@reduxjs/toolkit'
import  useReducer  from './user/userSlice';
import { persistReducer }  from 'redux-persist'
import storage from 'redux-persist/lib/storage';
import persistStore from 'redux-persist/es/persistStore';

const rootReducer = combineReducers({user: useReducer});

const persistConfig = {
  key: 'root',
  storage,
  version: 2,
  migrate: (state) => {
    // Return a Promise as required by redux-persist
    return Promise.resolve().then(() => {
      // Handle migration from old state structure
      if (state && typeof state === 'object') {
        // If state has unexpected keys at root level, restructure it
        if ('isAuthenticated' in state || 'token' in state || 'isLoading' in state || 'resetPasswordEmail' in state) {
          return {
            user: {
              currentUser: state.currentUser || null,
              error: state.error || null,
              loading: state.loading || false,
            },
            _persist: state._persist
          };
        }
        // If user state is null or doesn't have proper structure, reset it
        if (!state.user || typeof state.user !== 'object' || !('currentUser' in state.user)) {
          return {
            user: {
              currentUser: null,
              error: null,
              loading: false,
            },
            _persist: state._persist
          };
        }
      }
      return state;
    });
  }
}

const persistedReducer = persistReducer(persistConfig, rootReducer);

export const store = configureStore({
  reducer: persistedReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
        serializableCheck: false,
    }),
});

export const persistor = persistStore(store, null, () => {
  // Callback after rehydration - verify state integrity
  const state = store.getState();
  if (!state.user || typeof state.user !== 'object') {
    console.warn('Invalid persisted state detected, resetting...');
    persistor.purge().then(() => {
      window.location.reload();
    });
  }
});